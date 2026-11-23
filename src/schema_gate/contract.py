"""Declarative schema-boundary contract definitions and structured diagnostics.

Mirrors the Isabelle/HOL 2026 formalization (session RC_SchemaBoundary, zero sorry):
  - G1: Syntactic import compliance
  - G2: Concept decompression (single authoritative concept axis per column)
  - G3: Single-writer ownership (only owner_module mutates table.column)
  - G4: Append-only history integrity (no UPDATE/DELETE on AppendOnlyFact tables/columns)
  - G5: Domain closure (only declared allowed_tags written to constrained columns)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping
import fnmatch
import hashlib
import json

VALID_DATA_CLASSES = frozenset({
    "MutableState",
    "AppendOnlyFact",
    "DerivedProj",
    "ReconciledExt",
})


@dataclass(frozen=True)
class ColumnContract:
    table: str
    column: str
    owner_module: str
    concept: str
    data_class: str
    allowed_tags: frozenset[str] = frozenset()
    description: str = ""

    def __post_init__(self) -> None:
        if self.data_class not in VALID_DATA_CLASSES:
            raise ValueError(
                f"Invalid data_class {self.data_class!r} for {self.table}.{self.column}; "
                f"expected one of {sorted(VALID_DATA_CLASSES)}"
            )

    @property
    def fq_name(self) -> str:
        return f"{self.table.lower()}.{self.column.lower()}"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "table": self.table,
            "column": self.column,
            "owner_module": self.owner_module,
            "concept": self.concept,
            "data_class": self.data_class,
            "allowed_tags": sorted(self.allowed_tags),
        }
        if self.description:
            out["description"] = self.description
        return out


@dataclass
class SchemaContract:
    columns: dict[str, ColumnContract]  # key: "table.column" (lowercase)
    forbidden_imports: set[tuple[str, str]] = field(default_factory=set)
    module_globs: dict[str, list[str]] = field(default_factory=dict)  # module -> path globs
    table_aliases: dict[str, str] = field(default_factory=dict)  # model/var alias -> canonical table
    contract_id: str = "schema-contract-v1"
    sha256: str = ""
    source_path: str | None = None

    def tables_by_name(self) -> dict[str, list[ColumnContract]]:
        grouped: dict[str, list[ColumnContract]] = {}
        for cc in self.columns.values():
            grouped.setdefault(cc.table.lower(), []).append(cc)
        return grouped

    def resolve_table(self, raw_name: str) -> str | None:
        """Resolve a table, model, or variable identifier to a contracted table name."""
        norm = _normalize_identifier(raw_name)
        tables = {cc.table.lower() for cc in self.columns.values()}
        if norm in self.table_aliases:
            cand = self.table_aliases[norm].lower()
            if cand in tables:
                return cand
        if norm in tables:
            return norm
        # Singular/plural and camelCase -> snake_case fallback
        candidates = [
            norm,
            f"{norm}s",
            f"{norm}es",
            norm[:-1] + "ies" if norm.endswith("y") else "",
            norm[:-1] if norm.endswith("s") else "",
        ]
        for cand in candidates:
            if cand and cand in tables:
                return cand
        return None

    def infer_module_for_path(self, file_path: str | Path) -> str | None:
        """Infer owning module name from file path using module_globs or directory conventions."""
        norm_path = str(file_path).replace("\\", "/").lstrip("./")
        for mod, globs in self.module_globs.items():
            for pat in globs:
                if fnmatch.fnmatch(norm_path, pat) or fnmatch.fnmatch(Path(norm_path).name, pat):
                    return mod

        known_modules = {cc.owner_module for cc in self.columns.values()}
        for src, dst in self.forbidden_imports:
            known_modules.add(src)
            known_modules.add(dst)

        parts = [p.lower() for p in Path(norm_path).with_suffix("").parts]
        # Prefer deepest matching directory/stem segment that corresponds to a known module
        for part in reversed(parts):
            if part in known_modules:
                return part
        return parts[-1] if parts else None

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, Any],
        *,
        sha256: str = "",
        source_path: str | None = None,
    ) -> "SchemaContract":
        if not isinstance(raw, Mapping):
            raise ValueError("Schema contract must be a JSON object")
        raw_cols = raw.get("columns")
        if not isinstance(raw_cols, list):
            raise ValueError("Schema contract requires a 'columns' list")
        cols: dict[str, ColumnContract] = {}
        for item in raw_cols:
            cc = ColumnContract(
                table=str(item["table"]).lower(),
                column=str(item["column"]).lower(),
                owner_module=str(item["owner_module"]),
                concept=str(item["concept"]),
                data_class=str(item["data_class"]),
                allowed_tags=frozenset(str(t) for t in item.get("allowed_tags", [])),
                description=str(item.get("description", "")),
            )
            cols[cc.fq_name] = cc

        forb: set[tuple[str, str]] = set()
        for pair in raw.get("forbidden_imports", []):
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise ValueError(f"Invalid forbidden_imports entry: {pair!r}")
            forb.add((str(pair[0]), str(pair[1])))

        mod_globs: dict[str, list[str]] = {}
        for mod, pats in (raw.get("module_globs") or {}).items():
            mod_globs[str(mod)] = [str(p) for p in (pats if isinstance(pats, list) else [pats])]

        aliases = {
            _normalize_identifier(str(k)): str(v).lower()
            for k, v in (raw.get("table_aliases") or {}).items()
        }

        return cls(
            columns=cols,
            forbidden_imports=forb,
            module_globs=mod_globs,
            table_aliases=aliases,
            contract_id=str(raw.get("contract_id", "schema-contract-v1")),
            sha256=sha256,
            source_path=source_path,
        )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "SchemaContract":
        p = Path(path)
        raw_bytes = p.read_bytes()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        data = json.loads(raw_bytes.decode("utf-8"))
        return cls.from_dict(data, sha256=digest, source_path=str(p.resolve()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "sha256": self.sha256,
            "columns": [cc.to_dict() for cc in self.columns.values()],
            "forbidden_imports": sorted([list(p) for p in self.forbidden_imports]),
            "module_globs": dict(self.module_globs),
            "table_aliases": dict(self.table_aliases),
        }


@dataclass(frozen=True)
class Violation:
    rule: str  # G1 | G2 | G3 | G4 | G5
    code: str
    file: str
    line: int
    module: str
    target: str
    message: str
    repair_hint: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckReport:
    allowed: bool
    violations: list[Violation] = field(default_factory=list)
    files_checked: int = 0
    writes_inspected: int = 0
    elapsed_ms: float = 0.0
    contract_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "contract_id": self.contract_id,
            "files_checked": self.files_checked,
            "writes_inspected": self.writes_inspected,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
        }

    def format_text(self) -> str:
        if self.allowed:
            return (
                f"SchemaGate PASS ({self.files_checked} file(s), "
                f"{self.writes_inspected} write(s) inspected in {self.elapsed_ms:.2f} ms)"
            )
        lines = [
            f"SchemaGate BLOCK: {len(self.violations)} violation(s) across {self.files_checked} file(s):"
        ]
        for idx, v in enumerate(self.violations, 1):
            loc = f"{v.file}:{v.line}" if v.file else f"<module:{v.module}>:{v.line}"
            lines.append(f"  [{idx}] {v.code} ({v.rule}) at {loc}")
            lines.append(f"      Cause : {v.message}")
            lines.append(f"      Repair: {v.repair_hint}")
        return "\n".join(lines)

    def to_sarif(self) -> dict[str, Any]:
        """Export violations in SARIF 2.1.0 format for GitHub Code Scanning."""
        rules_meta = {
            "G1_FORBIDDEN_IMPORT": "Forbidden cross-module syntactic import",
            "G2_CONCEPT_COMPRESSION": "Multiple domain concepts compressed into a single column",
            "G3_FOREIGN_WRITER": "Foreign module mutates a column owned by another module",
            "G4_APPEND_ONLY_OVERWRITE": "Destructive UPDATE or DELETE on an AppendOnlyFact ledger",
            "G5_UNDECLARED_TAG": "Undeclared sentinel/enum value written outside closed domain",
        }
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SchemaGate",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/iannil/schema-gate",
                            "rules": [
                                {"id": k, "shortDescription": {"text": desc}}
                                for k, desc in rules_meta.items()
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": v.code,
                            "level": "error",
                            "message": {"text": f"{v.message} | Repair: {v.repair_hint}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": v.file or f"{v.module}.py"},
                                        "region": {"startLine": max(1, v.line)},
                                    }
                                }
                            ],
                        }
                        for v in self.violations
                    ],
                }
            ],
        }


def _normalize_identifier(name: str) -> str:
    """Convert CamelCase/kebab-case identifiers to lowercase snake_case."""
    out: list[str] = []
    for i, ch in enumerate(name.strip()):
        if ch in ("-", " "):
            out.append("_")
        elif ch.isupper() and i > 0 and (name[i - 1].islower() or (i + 1 < len(name) and name[i + 1].islower())):
            out.append("_")
            out.append(ch.lower())
        else:
            out.append(ch.lower())
    return "".join(out)
