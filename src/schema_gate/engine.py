"""Deterministic multi-language SchemaGate static analysis engine (G1-G5).

Supports:
  - Python (.py): AST imports, raw/parameterized SQL, f-strings / string concat,
    SQLAlchemy (`update(Table).values(...)`, `delete(Table)`, `query(Model).update(...)`),
    Django ORM (`Model.objects...update(...)`, `.delete()`), attribute/subscript mutations.
  - TypeScript / JavaScript (.ts, .tsx, .js, .mjs, .cjs): ES/CJS imports, raw SQL
    strings/template literals, Prisma (`prisma.<model>.update/updateMany/upsert/delete`),
    Drizzle (`db.update(<table>).set(...)`, `db.delete(<table>)`).
  - SQL migrations (.sql): UPDATE, DELETE, REPLACE, INSERT, ALTER TABLE DROP COLUMN.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
import ast
import re
import subprocess
import time

from .contract import CheckReport, ColumnContract, SchemaContract, Violation, _normalize_identifier

SUPPORTED_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".sql"})

# ---- Shared SQL regexes -----------------------------------------------------

SQL_UPDATE_RE = re.compile(
    r"\bUPDATE\s+[`\"']?([a-zA-Z_][\w.]*)[`\"']?\s+SET\s+(.*?)(?:\bWHERE\b|\bRETURNING\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)
SQL_ASSIGN_RE = re.compile(
    r"[`\"']?([a-zA-Z_][\w]*)[`\"']?\s*=\s*"
    r"(?:'([^']*)'|\"([^\"]*)\"|(-?\d+)|:([a-zA-Z_]\w*)|%\(([a-zA-Z_]\w*)\)s|%s|\?|\$(\d+))"
)
SQL_DELETE_RE = re.compile(
    r"\bDELETE\s+FROM\s+[`\"']?([a-zA-Z_][\w.]*)[`\"']?",
    re.IGNORECASE,
)
SQL_REPLACE_RE = re.compile(
    r"\bREPLACE\s+INTO\s+[`\"']?([a-zA-Z_][\w.]*)[`\"']?\s*\(([^)]+)\)",
    re.IGNORECASE,
)
SQL_INSERT_RE = re.compile(
    r"\bINSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+[`\"']?([a-zA-Z_][\w.]*)[`\"']?\s*\(([^)]+)\)"
    r"(?:\s*VALUES\s*\(([^)]*)\))?",
    re.IGNORECASE | re.DOTALL,
)
SQL_ALTER_DROP_RE = re.compile(
    r"\bALTER\s+TABLE\s+[`\"']?([a-zA-Z_][\w.]*)[`\"']?\s+DROP\s+(?:COLUMN\s+)?[`\"']?([a-zA-Z_][\w]*)[`\"']?",
    re.IGNORECASE,
)
CONCEPT_TAG_RE = re.compile(r"(?:#|//|--)\s*concept\s*:\s*([a-zA-Z0-9_.-]+)")

# ---- TS/JS import & ORM regexes ---------------------------------------------

TS_IMPORT_RE = re.compile(
    r"""(?:import\s+[^;]*?\s+from\s+|import\s+|require\s*\(\s*)['"]([^'"]+)['"]"""
)
PRISMA_MUT_RE = re.compile(
    r"\b(?:prisma|tx|client)\.([a-zA-Z_]\w*)\.(update|updateMany|upsert|delete|deleteMany|create|createMany)\s*\(",
    re.MULTILINE,
)
DRIZZLE_UPDATE_RE = re.compile(
    r"\b(?:db|tx)\.update\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*\.set\s*\(",
    re.MULTILINE,
)
DRIZZLE_DELETE_RE = re.compile(
    r"\b(?:db|tx)\.delete\s*\(\s*([a-zA-Z_]\w*)\s*\)",
    re.MULTILINE,
)
DRIZZLE_INSERT_RE = re.compile(
    r"\b(?:db|tx)\.insert\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*\.values\s*\(",
    re.MULTILINE,
)
JS_OBJ_PAIR_RE = re.compile(
    r"""([a-zA-Z_]\w*)\s*:\s*(?:'([^']*)'|"([^"]*)"|`([^`$]*)`|(-?\d+))"""
)
JS_STRING_SQL_RE = re.compile(
    r"""(?:`([^`]+)`|'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")""",
    re.DOTALL,
)


@dataclass(frozen=True)
class WriteEvent:
    fq_col: str
    op: str  # UPDATE | DELETE | INSERT | DROP
    tags: tuple[str, ...] = ()
    line: int = 1
    concepts: frozenset[str] = frozenset()


@dataclass
class PatchFindings:
    module_name: str
    file_path: str = ""
    imports: list[tuple[str, int]] = field(default_factory=list)  # (imported_mod, line)
    writes: list[WriteEvent] = field(default_factory=list)


def _strip_schema_prefix(raw_table: str) -> str:
    return raw_table.split(".")[-1].strip().strip("`\"'").lower()


def _infer_concepts(
    fq_col: str,
    tags: Sequence[str],
    line: int,
    source_lines: Sequence[str],
    contract: SchemaContract,
) -> frozenset[str]:
    found: set[str] = set()
    if 1 <= line <= len(source_lines):
        m = CONCEPT_TAG_RE.search(source_lines[line - 1])
        if m:
            found.add(m.group(1))
    cc = contract.columns.get(fq_col)
    if cc:
        for t in tags:
            if cc.allowed_tags and t not in cc.allowed_tags:
                found.add(f"undeclared_tag:{t}")
            else:
                found.add(cc.concept)
    return frozenset(found)


def _split_sql_values(raw_values: str) -> list[str | None]:
    vals: list[str | None] = []
    for part in raw_values.split(","):
        s = part.strip()
        if (len(s) >= 2 and s[0] == "'" and s[-1] == "'") or (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
            vals.append(s[1:-1])
        elif re.fullmatch(r"-?\d+", s):
            vals.append(s)
        else:
            vals.append(None)
    return vals


def inspect_sql_text(
    text: str,
    line: int,
    named_params: dict[str, str],
    pos_params: list[str],
    source_lines: Sequence[str],
    contract: SchemaContract,
    findings: PatchFindings,
) -> None:
    """Extract UPDATE / DELETE / REPLACE / INSERT / ALTER DROP mutations from SQL text."""
    tables_map = contract.tables_by_name()

    # 1. UPDATE table SET col = val ...
    for um in SQL_UPDATE_RE.finditer(text):
        raw_tbl = _strip_schema_prefix(um.group(1))
        table = contract.resolve_table(raw_tbl) or raw_tbl
        set_clause = um.group(2)
        pos_idx = 0
        for am in SQL_ASSIGN_RE.finditer(set_clause):
            col = _normalize_identifier(am.group(1))
            tag = am.group(2) if am.group(2) is not None else (
                am.group(3) if am.group(3) is not None else am.group(4)
            )
            if tag is None:
                pname = am.group(5) or am.group(6)
                dollar_idx = am.group(7)
                if pname and pname in named_params:
                    tag = named_params[pname]
                elif dollar_idx and int(dollar_idx) - 1 < len(pos_params):
                    tag = pos_params[int(dollar_idx) - 1]
                elif pos_idx < len(pos_params):
                    tag = pos_params[pos_idx]
                    pos_idx += 1
            tags = (tag,) if tag is not None else ()
            fq = f"{table}.{col}"
            concepts = _infer_concepts(fq, tags, line, source_lines, contract)
            findings.writes.append(WriteEvent(fq_col=fq, op="UPDATE", tags=tags, line=line, concepts=concepts))

    # 2. DELETE FROM table -> destructive overwrite on every contracted column in table
    for dm in SQL_DELETE_RE.finditer(text):
        raw_tbl = _strip_schema_prefix(dm.group(1))
        table = contract.resolve_table(raw_tbl) or raw_tbl
        cols = tables_map.get(table, [])
        for cc in cols:
            findings.writes.append(
                WriteEvent(fq_col=cc.fq_name, op="DELETE", tags=(), line=line, concepts=frozenset())
            )

    # 3. REPLACE INTO / INSERT OR REPLACE INTO -> destructive overwrite
    for rm in SQL_REPLACE_RE.finditer(text):
        raw_tbl = _strip_schema_prefix(rm.group(1))
        table = contract.resolve_table(raw_tbl) or raw_tbl
        cols = [_normalize_identifier(c) for c in rm.group(2).split(",")]
        for col in cols:
            fq = f"{table}.{col}"
            findings.writes.append(WriteEvent(fq_col=fq, op="UPDATE", tags=(), line=line))

    # 4. INSERT INTO table (cols) [VALUES (...)]
    for im in SQL_INSERT_RE.finditer(text):
        is_or_replace = bool(re.match(r"\bINSERT\s+OR\s+REPLACE\b", im.group(0), re.IGNORECASE))
        raw_tbl = _strip_schema_prefix(im.group(1))
        table = contract.resolve_table(raw_tbl) or raw_tbl
        cols = [_normalize_identifier(c) for c in im.group(2).split(",")]
        raw_vals = im.group(3)
        parsed_vals = _split_sql_values(raw_vals) if raw_vals is not None else []
        op = "UPDATE" if is_or_replace else "INSERT"
        for idx, col in enumerate(cols):
            val = parsed_vals[idx] if idx < len(parsed_vals) else None
            tags = (val,) if val is not None else ()
            fq = f"{table}.{col}"
            concepts = _infer_concepts(fq, tags, line, source_lines, contract)
            findings.writes.append(WriteEvent(fq_col=fq, op=op, tags=tags, line=line, concepts=concepts))

    # 5. ALTER TABLE table DROP COLUMN col
    for adm in SQL_ALTER_DROP_RE.finditer(text):
        raw_tbl = _strip_schema_prefix(adm.group(1))
        table = contract.resolve_table(raw_tbl) or raw_tbl
        col = _normalize_identifier(adm.group(2))
        fq = f"{table}.{col}"
        findings.writes.append(WriteEvent(fq_col=fq, op="DROP", tags=(), line=line))


# ---- Python AST extractor ---------------------------------------------------


def _eval_string_expr(node: ast.AST, str_env: dict[str, str]) -> str | None:
    """Best-effort static reconstruction of string literals, f-strings, and + concatenations."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in str_env:
        return str_env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_string_expr(node.left, str_env)
        right = _eval_string_expr(node.right, str_env)
        if left is not None or right is not None:
            return (left or "") + (right or "")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                inner = _eval_string_expr(v.value, str_env)
                parts.append(inner if inner is not None else ":_fexpr")
        return "".join(parts)
    return None


def _extract_call_param_strings(
    call_node: ast.Call, str_env: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    named: dict[str, str] = {}
    positional: list[str] = []
    if len(call_node.args) >= 2:
        p = call_node.args[1]
        if isinstance(p, ast.Dict):
            for k, v in zip(p.keys, p.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    if isinstance(v, ast.Constant) and isinstance(v.value, (str, int)):
                        named[k.value] = str(v.value)
                    elif isinstance(v, ast.Name) and v.id in str_env:
                        named[k.value] = str_env[v.id]
        elif isinstance(p, (ast.Tuple, ast.List)):
            for el in p.elts:
                if isinstance(el, ast.Constant) and isinstance(el.value, (str, int)):
                    positional.append(str(el.value))
                elif isinstance(el, ast.Name) and el.id in str_env:
                    positional.append(str_env[el.id])
    return named, positional


def _extract_kw_or_dict_pairs(call_node: ast.Call, str_env: dict[str, str]) -> list[tuple[str, str | None]]:
    pairs: list[tuple[str, str | None]] = []
    for kw in call_node.keywords:
        if kw.arg:
            val: str | None = None
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, (str, int)):
                val = str(kw.value.value)
            elif isinstance(kw.value, ast.Name) and kw.value.id in str_env:
                val = str_env[kw.value.id]
            pairs.append((_normalize_identifier(kw.arg), val))
    if call_node.args and isinstance(call_node.args[0], ast.Dict):
        d = call_node.args[0]
        for k, v in zip(d.keys, d.values):
            col_name: str | None = None
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                col_name = _normalize_identifier(k.value)
            elif isinstance(k, ast.Attribute):
                col_name = _normalize_identifier(k.attr)
            if col_name:
                val = None
                if isinstance(v, ast.Constant) and isinstance(v.value, (str, int)):
                    val = str(v.value)
                elif isinstance(v, ast.Name) and v.id in str_env:
                    val = str_env[v.id]
                pairs.append((col_name, val))
    return pairs


def _find_root_model_in_chain(node: ast.AST) -> str | None:
    """Walk chained ORM calls like Model.objects.filter(...).update(...) or update(User).where(...).values(...)."""
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, ast.Call):
            func = cur.func
            if isinstance(func, ast.Name) and func.id in ("update", "delete", "insert") and cur.args:
                arg0 = cur.args[0]
                if isinstance(arg0, ast.Name):
                    return arg0.id
                if isinstance(arg0, ast.Attribute):
                    return arg0.attr
            if isinstance(func, ast.Attribute) and func.attr == "query" and cur.args:
                arg0 = cur.args[0]
                if isinstance(arg0, ast.Name):
                    return arg0.id
            cur = func
        elif isinstance(cur, ast.Attribute):
            if cur.attr == "objects" and isinstance(cur.value, ast.Name):
                return cur.value.id
            cur = cur.value
        else:
            break
    return None


def _extract_python_findings(
    module_name: str,
    source_code: str,
    contract: SchemaContract,
    file_path: str = "",
) -> PatchFindings:
    findings = PatchFindings(module_name=module_name, file_path=file_path)
    tree = ast.parse(source_code)
    source_lines = source_code.splitlines()

    # Track simple local string/int variable bindings for light intra-function dataflow
    str_env: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            val = _eval_string_expr(node.value, str_env)
            if val is not None:
                str_env[node.targets[0].id] = val
            elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                str_env[node.targets[0].id] = str(node.value.value)

    # 1. Syntactic imports (G1)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                findings.imports.append((alias.name.split(".")[0], getattr(node, "lineno", 1)))
        elif isinstance(node, ast.ImportFrom) and node.module:
            findings.imports.append((node.module.split(".")[0], getattr(node, "lineno", 1)))

    visited_expr_ids: set[int] = set()
    tables_map = contract.tables_by_name()

    # 2. Call-site SQL (execute / raw / text) and ORM (SQLAlchemy / Django)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", 1)

        # 2a. SQL call with params: db.execute(sql_expr, params)
        if node.args:
            sql_expr = node.args[0]
            sql_text = _eval_string_expr(sql_expr, str_env)
            if sql_text is not None:
                named_p, pos_p = _extract_call_param_strings(node, str_env)
                inspect_sql_text(sql_text, lineno, named_p, pos_p, source_lines, contract, findings)
                visited_expr_ids.add(id(sql_expr))
                for child in ast.walk(sql_expr):
                    visited_expr_ids.add(id(child))

        # 2b. ORM call chains: SQLAlchemy `.values(...)` / `.update(...)` / `delete(Table)` & Django `.objects...update(...)` / `.delete()`
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in ("values", "update"):
                model_raw = _find_root_model_in_chain(node.func.value)
                table = contract.resolve_table(model_raw) if model_raw else None
                if table:
                    pairs = _extract_kw_or_dict_pairs(node, str_env)
                    op = "INSERT" if _chain_contains_call(node.func.value, "insert") else "UPDATE"
                    for col, val in pairs:
                        fq = f"{table}.{col}"
                        tags = (val,) if val is not None else ()
                        concepts = _infer_concepts(fq, tags, lineno, source_lines, contract)
                        findings.writes.append(WriteEvent(fq_col=fq, op=op, tags=tags, line=lineno, concepts=concepts))
            elif method == "delete":
                model_raw = _find_root_model_in_chain(node.func.value)
                table = contract.resolve_table(model_raw) if model_raw else None
                if table:
                    for cc in tables_map.get(table, []):
                        findings.writes.append(WriteEvent(fq_col=cc.fq_name, op="DELETE", line=lineno))
        elif isinstance(node.func, ast.Name) and node.func.id == "delete" and node.args:
            arg0 = node.args[0]
            raw = arg0.id if isinstance(arg0, ast.Name) else (arg0.attr if isinstance(arg0, ast.Attribute) else None)
            table = contract.resolve_table(raw) if raw else None
            if table:
                for cc in tables_map.get(table, []):
                    findings.writes.append(WriteEvent(fq_col=cc.fq_name, op="DELETE", line=lineno))

    # 3. Remaining standalone SQL strings/f-strings & ORM attribute/subscript writes
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        if id(node) not in visited_expr_ids and isinstance(node, (ast.Constant, ast.JoinedStr)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                inspect_sql_text(node.value, lineno, {}, [], source_lines, contract, findings)
            elif isinstance(node, ast.JoinedStr):
                txt = _eval_string_expr(node, str_env)
                if txt:
                    inspect_sql_text(txt, lineno, {}, [], source_lines, contract, findings)
                    for child in ast.walk(node):
                        visited_expr_ids.add(id(child))

        if isinstance(node, ast.Assign):
            rhs_tags: list[str] = []
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, int)):
                rhs_tags.append(str(node.value.value))
            elif isinstance(node.value, ast.Name) and node.value.id in str_env:
                rhs_tags.append(str_env[node.value.id])
            for tgt in node.targets:
                fq = None
                if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                    table = contract.resolve_table(tgt.value.id)
                    col = _normalize_identifier(tgt.attr)
                    if table and f"{table}.{col}" in contract.columns:
                        fq = f"{table}.{col}"
                elif (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Name)
                    and isinstance(tgt.slice, ast.Constant)
                    and isinstance(tgt.slice.value, str)
                ):
                    table = contract.resolve_table(tgt.value.id)
                    col = _normalize_identifier(tgt.slice.value)
                    if table and f"{table}.{col}" in contract.columns:
                        fq = f"{table}.{col}"
                if fq:
                    tags_t = tuple(rhs_tags)
                    concepts = _infer_concepts(fq, tags_t, lineno, source_lines, contract)
                    findings.writes.append(WriteEvent(fq_col=fq, op="UPDATE", tags=tags_t, line=lineno, concepts=concepts))

    return findings


def _chain_contains_call(node: ast.AST, func_name: str) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id == func_name:
                return True
            if isinstance(child.func, ast.Attribute) and child.func.attr == func_name:
                return True
    return False


# ---- TypeScript / JavaScript extractor (Prisma / Drizzle / raw SQL) ---------


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _extract_balanced_block(text: str, start_idx: int, open_ch: str, close_ch: str) -> str:
    depth = 0
    in_str: str | None = None
    i = start_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < len(text):
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"', "`"):
                in_str = ch
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return text[start_idx : i + 1]
        i += 1
    return text[start_idx:]


def _extract_js_object_writes(
    body: str,
    table: str,
    op: str,
    base_line: int,
    source_lines: Sequence[str],
    contract: SchemaContract,
    findings: PatchFindings,
) -> None:
    for pm in JS_OBJ_PAIR_RE.finditer(body):
        col = _normalize_identifier(pm.group(1))
        val = next((g for g in pm.groups()[1:] if g is not None), None)
        fq = f"{table}.{col}"
        if fq not in contract.columns:
            continue
        tags = (val,) if val is not None else ()
        line = base_line + body.count("\n", 0, pm.start())
        concepts = _infer_concepts(fq, tags, line, source_lines, contract)
        findings.writes.append(WriteEvent(fq_col=fq, op=op, tags=tags, line=line, concepts=concepts))


def _extract_ts_js_findings(
    module_name: str,
    source_code: str,
    contract: SchemaContract,
    file_path: str = "",
) -> PatchFindings:
    findings = PatchFindings(module_name=module_name, file_path=file_path)
    source_lines = source_code.splitlines()
    tables_map = contract.tables_by_name()

    # 1. Imports (G1)
    for m in TS_IMPORT_RE.finditer(source_code):
        raw_imp = m.group(1)
        line = _line_of_offset(source_code, m.start())
        parts = [p for p in raw_imp.replace("\\", "/").split("/") if p and p not in (".", "..")]
        if parts:
            # Record both top-level and leaf segments so forbidden_imports works with relative or package paths
            for seg in {parts[0], parts[-1].split(".")[0]}:
                findings.imports.append((seg, line))

    # 2. Raw SQL inside template literals or quotes
    for sm in JS_STRING_SQL_RE.finditer(source_code):
        text = next((g for g in sm.groups() if g is not None), "")
        if any(kw in text.upper() for kw in ("UPDATE ", "DELETE ", "INSERT ", "REPLACE ", "ALTER ")):
            line = _line_of_offset(source_code, sm.start())
            inspect_sql_text(text, line, {}, [], source_lines, contract, findings)

    # 3. Prisma calls: prisma.user.update({ where: ..., data: { status: 'risk_locked' } })
    for pm in PRISMA_MUT_RE.finditer(source_code):
        model_raw, method = pm.group(1), pm.group(2)
        table = contract.resolve_table(model_raw)
        if not table:
            continue
        line = _line_of_offset(source_code, pm.start())
        if method in ("delete", "deleteMany"):
            for cc in tables_map.get(table, []):
                findings.writes.append(WriteEvent(fq_col=cc.fq_name, op="DELETE", line=line))
            continue
        args_block = _extract_balanced_block(source_code, pm.end() - 1, "(", ")")
        op = "INSERT" if method in ("create", "createMany") else "UPDATE"
        # Look for `data: { ... }` or `update: { ... }` blocks inside Prisma call
        matched_sub = False
        for key in ("data", "update", "create"):
            km = re.search(rf"\b{key}\s*:\s*\{{", args_block)
            if km:
                matched_sub = True
                obj_block = _extract_balanced_block(args_block, km.end() - 1, "{", "}")
                sub_op = "INSERT" if (method in ("create", "createMany") or key == "create") else "UPDATE"
                sub_line = line + args_block.count("\n", 0, km.start())
                _extract_js_object_writes(obj_block, table, sub_op, sub_line, source_lines, contract, findings)
        if not matched_sub:
            _extract_js_object_writes(args_block, table, op, line, source_lines, contract, findings)

    # 4. Drizzle ORM: db.update(users).set({ status: 'risk_locked' }), db.delete(paymentIntents), db.insert(tbl).values({...})
    for dm in DRIZZLE_UPDATE_RE.finditer(source_code):
        table = contract.resolve_table(dm.group(1))
        if not table:
            continue
        line = _line_of_offset(source_code, dm.start())
        block = _extract_balanced_block(source_code, dm.end() - 1, "(", ")")
        _extract_js_object_writes(block, table, "UPDATE", line, source_lines, contract, findings)

    for dm in DRIZZLE_DELETE_RE.finditer(source_code):
        table = contract.resolve_table(dm.group(1))
        if not table:
            continue
        line = _line_of_offset(source_code, dm.start())
        for cc in tables_map.get(table, []):
            findings.writes.append(WriteEvent(fq_col=cc.fq_name, op="DELETE", line=line))

    for dm in DRIZZLE_INSERT_RE.finditer(source_code):
        table = contract.resolve_table(dm.group(1))
        if not table:
            continue
        line = _line_of_offset(source_code, dm.start())
        block = _extract_balanced_block(source_code, dm.end() - 1, "(", ")")
        _extract_js_object_writes(block, table, "INSERT", line, source_lines, contract, findings)

    return findings


# ---- SQL migration file extractor -------------------------------------------


def _extract_sql_file_findings(
    module_name: str,
    source_code: str,
    contract: SchemaContract,
    file_path: str = "",
) -> PatchFindings:
    findings = PatchFindings(module_name=module_name, file_path=file_path)
    source_lines = source_code.splitlines()
    offset = 0
    for stmt in source_code.split(";"):
        if stmt.strip():
            line = _line_of_offset(source_code, offset)
            inspect_sql_text(stmt, line, {}, [], source_lines, contract, findings)
        offset += len(stmt) + 1
    return findings


# ---- Public extraction & G1-G5 evaluation -----------------------------------


def extract_patch_findings(
    module_name: str,
    source_code: str,
    contract: SchemaContract,
    *,
    language: str = "python",
    file_path: str = "",
) -> PatchFindings:
    """Deterministically analyze source code in Python, TypeScript/JS, or SQL."""
    lang = language.lower()
    if lang in ("py", "python"):
        return _extract_python_findings(module_name, source_code, contract, file_path=file_path)
    if lang in ("ts", "tsx", "js", "mjs", "cjs", "typescript", "javascript"):
        return _extract_ts_js_findings(module_name, source_code, contract, file_path=file_path)
    if lang == "sql":
        return _extract_sql_file_findings(module_name, source_code, contract, file_path=file_path)
    raise ValueError(f"Unsupported language: {language!r}")


def evaluate_import_guard(findings: PatchFindings, contract: SchemaContract) -> list[Violation]:
    """G1 only: syntactic cross-module import guard."""
    violations: list[Violation] = []
    seen: set[tuple[str, int]] = set()
    for imp, line in findings.imports:
        if (findings.module_name, imp) in contract.forbidden_imports and (imp, line) not in seen:
            seen.add((imp, line))
            violations.append(
                Violation(
                    rule="G1",
                    code="G1_FORBIDDEN_IMPORT",
                    file=findings.file_path,
                    line=line,
                    module=findings.module_name,
                    target=f"{findings.module_name}->{imp}",
                    message=f"Module '{findings.module_name}' imports forbidden module '{imp}'.",
                    repair_hint=f"Remove the import of '{imp}' and interact only through owned tables or explicit API/events.",
                )
            )
    return violations


def evaluate_schema_gate(findings: PatchFindings, contract: SchemaContract) -> list[Violation]:
    """Evaluate all five SchemaGate invariants (G1-G5) and return actionable violations."""
    violations = evaluate_import_guard(findings, contract)
    seen_keys: set[tuple[str, int, str]] = set()

    def add_v(v: Violation) -> None:
        key = (v.code, v.line, v.target)
        if key not in seen_keys:
            seen_keys.add(key)
            violations.append(v)

    for w in findings.writes:
        cc: ColumnContract | None = contract.columns.get(w.fq_col)
        if cc is None:
            continue

        # G3: Single-writer ownership
        if findings.module_name != cc.owner_module:
            add_v(
                Violation(
                    rule="G3",
                    code="G3_FOREIGN_WRITER",
                    file=findings.file_path,
                    line=w.line,
                    module=findings.module_name,
                    target=w.fq_col,
                    message=(
                        f"Module '{findings.module_name}' performs {w.op} on '{w.fq_col}', "
                        f"which is exclusively owned by module '{cc.owner_module}'."
                    ),
                    repair_hint=(
                        f"Do not write '{w.fq_col}' from '{findings.module_name}'. "
                        f"Write to a dedicated table/column owned by '{findings.module_name}' "
                        f"(concept decompression) or call '{cc.owner_module}'s public write interface."
                    ),
                )
            )

        # G4: Append-only history integrity
        if cc.data_class == "AppendOnlyFact" and w.op in ("UPDATE", "DELETE", "DROP"):
            add_v(
                Violation(
                    rule="G4",
                    code="G4_APPEND_ONLY_OVERWRITE",
                    file=findings.file_path,
                    line=w.line,
                    module=findings.module_name,
                    target=w.fq_col,
                    message=(
                        f"Destructive {w.op} on AppendOnlyFact column '{w.fq_col}' destroys "
                        f"historical intent and breaks deterministic reconciliation."
                    ),
                    repair_hint=(
                        f"Replace {w.op} with an append-only INSERT into '{cc.table}' recording the new "
                        f"event row instead of mutating or deleting prior history."
                    ),
                )
            )

        # G5: Domain closure
        if cc.allowed_tags:
            for t in w.tags:
                if t not in cc.allowed_tags:
                    allowed_str = ", ".join(sorted(cc.allowed_tags))
                    add_v(
                        Violation(
                            rule="G5",
                            code="G5_UNDECLARED_TAG",
                            file=findings.file_path,
                            line=w.line,
                            module=findings.module_name,
                            target=f"{w.fq_col}={t}",
                            message=(
                                f"Undeclared tag '{t}' written to '{w.fq_col}' "
                                f"(closed domain: [{allowed_str}])."
                            ),
                            repair_hint=(
                                f"Do not overload '{w.fq_col}' with undeclared tag '{t}'. "
                                f"Keep '{w.fq_col}' strictly within [{allowed_str}] and store "
                                f"distinct concepts in a dedicated owned column."
                            ),
                        )
                    )

        # G2: Concept decompression
        foreign_concepts = sorted(c for c in w.concepts if c != cc.concept)
        if foreign_concepts:
            add_v(
                Violation(
                    rule="G2",
                    code="G2_CONCEPT_COMPRESSION",
                    file=findings.file_path,
                    line=w.line,
                    module=findings.module_name,
                    target=w.fq_col,
                    message=(
                        f"Column '{w.fq_col}' (concept='{cc.concept}') is overloaded with "
                        f"foreign concept(s): {foreign_concepts}."
                    ),
                    repair_hint=(
                        f"Decompress the new concept into a separate column/table owned by "
                        f"'{findings.module_name}' instead of reusing '{w.fq_col}'."
                    ),
                )
            )

    return violations


def _language_for_path(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
        return "typescript"
    if ext == ".sql":
        return "sql"
    return None


def check_source(
    source_code: str,
    contract: SchemaContract,
    *,
    module_name: str,
    language: str = "python",
    file_path: str = "",
) -> CheckReport:
    t0 = time.perf_counter()
    findings = extract_patch_findings(
        module_name, source_code, contract, language=language, file_path=file_path
    )
    violations = evaluate_schema_gate(findings, contract)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return CheckReport(
        allowed=len(violations) == 0,
        violations=violations,
        files_checked=1,
        writes_inspected=len(findings.writes),
        elapsed_ms=elapsed_ms,
        contract_id=contract.contract_id,
    )


def check_file(
    file_path: str | Path,
    contract: SchemaContract,
    *,
    module_name: str | None = None,
) -> CheckReport:
    p = Path(file_path)
    lang = _language_for_path(p)
    if lang is None:
        return CheckReport(allowed=True, files_checked=0, contract_id=contract.contract_id)
    mod = module_name or contract.infer_module_for_path(p) or p.stem
    src = p.read_text(encoding="utf-8")
    return check_source(src, contract, module_name=mod, language=lang, file_path=str(p))


def check_paths(
    paths: Sequence[str | Path],
    contract: SchemaContract,
    *,
    module_name: str | None = None,
) -> CheckReport:
    t0 = time.perf_counter()
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in SUPPORTED_EXTENSIONS:
                    if not any(part in (".git", "node_modules", "__pycache__", ".venv", "dist", "build") for part in child.parts):
                        files.append(child)
        elif p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(p)

    all_violations: list[Violation] = []
    total_writes = 0
    for f in files:
        rep = check_file(f, contract, module_name=module_name)
        all_violations.extend(rep.violations)
        total_writes += rep.writes_inspected

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return CheckReport(
        allowed=len(all_violations) == 0,
        violations=all_violations,
        files_checked=len(files),
        writes_inspected=total_writes,
        elapsed_ms=elapsed_ms,
        contract_id=contract.contract_id,
    )


def collect_git_changed_files(*, staged: bool = False, diff_base: str | None = None, cwd: str | Path | None = None) -> list[Path]:
    cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR"]
    if staged:
        cmd.append("--cached")
    elif diff_base:
        cmd.append(f"{diff_base}...HEAD")
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True)
    base = Path(cwd) if cwd else Path.cwd()
    out: list[Path] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line:
            p = base / line
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
                out.append(p)
    return out
