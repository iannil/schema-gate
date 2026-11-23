"""Runtime DB-API 2.0 SQL proxy reusing the same declarative SchemaContract.

Closes the static-analysis boundary for dynamically concatenated SQL strings
and runtime ORM query builders during test suites or staging execution.
Works with sqlite3 and any Python DB-API 2.0 connection/cursor.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from .contract import SchemaContract, Violation
from .engine import PatchFindings, evaluate_schema_gate, inspect_sql_text


class SchemaBoundaryViolationError(RuntimeError):
    """Raised fail-closed before executing a SQL statement that violates G2-G5."""

    def __init__(self, sql: str, module_name: str, violations: list[Violation]) -> None:
        self.sql = sql
        self.module_name = module_name
        self.violations = violations
        summary = "; ".join(f"{v.code}: {v.message}" for v in violations)
        super().__init__(f"SchemaGate runtime block in module '{module_name}': {summary}")


def _coerce_params(params: Any) -> tuple[dict[str, str], list[str]]:
    if params is None:
        return {}, []
    if isinstance(params, dict):
        return {str(k): str(v) for k, v in params.items() if v is not None}, []
    if isinstance(params, (list, tuple)):
        return {}, [str(v) for v in params if v is not None]
    return {}, []


def validate_runtime_sql(
    sql: str,
    contract: SchemaContract,
    module_name: str,
    params: Any = None,
) -> list[Violation]:
    named_p, pos_p = _coerce_params(params)
    findings = PatchFindings(module_name=module_name, file_path="<runtime-sql>")
    inspect_sql_text(sql, 1, named_p, pos_p, sql.splitlines(), contract, findings)
    return evaluate_schema_gate(findings, contract)


class SchemaGateCursor:
    """Fail-closed DB-API 2.0 cursor wrapper enforcing G2-G5 at execution time."""

    def __init__(
        self,
        raw_cursor: Any,
        contract: SchemaContract,
        module_name: str,
        *,
        strict: bool = True,
        audit_log: list[dict[str, Any]] | None = None,
    ) -> None:
        self._cursor = raw_cursor
        self._contract = contract
        self._module_name = module_name
        self._strict = strict
        self._audit_log = audit_log if audit_log is not None else []

    def _guard(self, sql: str, params: Any = None) -> None:
        violations = validate_runtime_sql(sql, self._contract, self._module_name, params=params)
        if violations:
            self._audit_log.append({
                "module": self._module_name,
                "sql": sql,
                "blocked": self._strict,
                "violations": [v.to_dict() for v in violations],
            })
            if self._strict:
                raise SchemaBoundaryViolationError(sql, self._module_name, violations)

    def execute(self, sql: str, parameters: Any = None) -> Any:
        self._guard(sql, parameters)
        if parameters is None:
            return self._cursor.execute(sql)
        return self._cursor.execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]) -> Any:
        materialized = list(seq_of_parameters)
        for p in materialized:
            self._guard(sql, p)
        return self._cursor.executemany(sql, materialized)

    def executescript(self, sql_script: str) -> Any:
        for stmt in sql_script.split(";"):
            if stmt.strip():
                self._guard(stmt)
        return self._cursor.executescript(sql_script)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)

    def __iter__(self) -> Any:
        return iter(self._cursor)


class SchemaGateConnection:
    """Fail-closed DB-API 2.0 connection wrapper (compatible with sqlite3, psycopg2, etc.)."""

    def __init__(
        self,
        raw_conn: Any,
        contract: SchemaContract,
        module_name: str,
        *,
        strict: bool = True,
    ) -> None:
        self._conn = raw_conn
        self._contract = contract
        self._module_name = module_name
        self._strict = strict
        self.audit_log: list[dict[str, Any]] = []

    def cursor(self, *args: Any, **kwargs: Any) -> SchemaGateCursor:
        return SchemaGateCursor(
            self._conn.cursor(*args, **kwargs),
            self._contract,
            self._module_name,
            strict=self._strict,
            audit_log=self.audit_log,
        )

    def execute(self, sql: str, parameters: Any = None) -> Any:
        cur = self.cursor()
        return cur.execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]) -> Any:
        cur = self.cursor()
        return cur.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> Any:
        cur = self.cursor()
        return cur.executescript(sql_script)

    def __enter__(self) -> "SchemaGateConnection":
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        return self._conn.__exit__(exc_type, exc, tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def wrap_dbapi_connection(
    conn: Any,
    contract: SchemaContract,
    module_name: str,
    *,
    strict: bool = True,
) -> SchemaGateConnection:
    """Wrap any Python DB-API 2.0 connection with fail-closed SchemaGate enforcement."""
    return SchemaGateConnection(conn, contract, module_name, strict=strict)
