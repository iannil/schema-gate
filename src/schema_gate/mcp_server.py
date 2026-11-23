"""Zero-dependency JSON-RPC 2.0 MCP stdio server for schema-gate.

Allows Claude Code, Cursor, or any MCP-compatible coding agent to inspect
schema-boundary ownership contracts and pre-flight check patches/SQL before writing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import sys

from .contract import SchemaContract
from .engine import check_paths, check_source
from .runtime_proxy import validate_runtime_sql

TOOLS = [
    {
        "name": "schema_gate_inspect_contract",
        "description": "Inspect declared table/column owners, domain concepts, data classes (MutableState vs AppendOnlyFact), allowed enum tags, and forbidden imports before modifying schema or persistence code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Optional table name filter"},
                "module": {"type": "string", "description": "Optional owner module filter"},
            },
        },
    },
    {
        "name": "schema_gate_check_patch",
        "description": "Check a proposed Python, TypeScript/JS, or SQL code patch against G1-G5 schema-boundary invariants before applying it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Owning module name of the file being edited"},
                "source_code": {"type": "string", "description": "Proposed source code content"},
                "language": {"type": "string", "enum": ["python", "typescript", "javascript", "sql"], "default": "python"},
                "file_path": {"type": "string", "default": ""},
            },
            "required": ["module", "source_code"],
        },
    },
    {
        "name": "schema_gate_check_files",
        "description": "Scan one or more files or directories against the declarative SchemaGate contract (G1-G5).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "module": {"type": "string", "description": "Optional explicit module override"},
            },
            "required": ["paths"],
        },
    },
    {
        "name": "schema_gate_validate_sql",
        "description": "Validate a single SQL statement and optional bound parameters for a module against G2-G5.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string"},
                "sql": {"type": "string"},
                "params": {"type": "object"},
            },
            "required": ["module", "sql"],
        },
    },
]


class SchemaGateMCPServer:
    def __init__(self, contract_path: str | Path) -> None:
        self.contract_path = Path(contract_path)

    def _load_contract(self) -> SchemaContract:
        return SchemaContract.from_json_file(self.contract_path)

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        contract = self._load_contract()

        if name == "schema_gate_inspect_contract":
            table_filter = str(args.get("table", "")).lower()
            mod_filter = str(args.get("module", ""))
            cols = [
                cc.to_dict()
                for cc in contract.columns.values()
                if (not table_filter or cc.table.lower() == table_filter)
                and (not mod_filter or cc.owner_module == mod_filter)
            ]
            return {
                "contract_id": contract.contract_id,
                "sha256": contract.sha256,
                "columns": cols,
                "forbidden_imports": sorted([list(p) for p in contract.forbidden_imports]),
            }

        if name == "schema_gate_check_patch":
            rep = check_source(
                args["source_code"],
                contract,
                module_name=args["module"],
                language=str(args.get("language", "python")),
                file_path=str(args.get("file_path", "")),
            )
            return rep.to_dict()

        if name == "schema_gate_check_files":
            rep = check_paths(args["paths"], contract, module_name=args.get("module"))
            return rep.to_dict()

        if name == "schema_gate_validate_sql":
            violations = validate_runtime_sql(
                args["sql"],
                contract,
                args["module"],
                params=args.get("params"),
            )
            return {
                "allowed": len(violations) == 0,
                "violation_count": len(violations),
                "violations": [v.to_dict() for v in violations],
            }

        raise ValueError(f"Unknown tool: {name}")

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params") or {}

        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "schema-gate", "version": "0.1.0"},
                },
            }
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            try:
                payload = self._call_tool(name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)}, ensure_ascii=False)}],
                        "isError": True,
                    },
                }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
            else:
                resp = self.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
