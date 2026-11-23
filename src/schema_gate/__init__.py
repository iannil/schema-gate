"""schema-gate: Fail-closed Schema-Boundary Contract Gate for AI coding agents."""

from .contract import CheckReport, ColumnContract, SchemaContract, Violation
from .engine import (
    PatchFindings,
    WriteEvent,
    check_file,
    check_paths,
    check_source,
    evaluate_import_guard,
    evaluate_schema_gate,
    extract_patch_findings,
)
from .runtime_proxy import (
    SchemaBoundaryViolationError,
    SchemaGateConnection,
    SchemaGateCursor,
    wrap_dbapi_connection,
)

__all__ = [
    "CheckReport",
    "ColumnContract",
    "PatchFindings",
    "SchemaBoundaryViolationError",
    "SchemaContract",
    "SchemaGateConnection",
    "SchemaGateCursor",
    "Violation",
    "WriteEvent",
    "check_file",
    "check_paths",
    "check_source",
    "evaluate_import_guard",
    "evaluate_schema_gate",
    "extract_patch_findings",
    "wrap_dbapi_connection",
]

__version__ = "0.1.1"
