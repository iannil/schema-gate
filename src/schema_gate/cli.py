"""Command-line interface for schema-gate."""
from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys

from .contract import SchemaContract
from .engine import check_paths, collect_git_changed_files
from .hooks import run_claude_code_hook
from .mcp_server import SchemaGateMCPServer

STARTER_CONTRACT = {
    "contract_id": "my-service-schema-v1",
    "columns": [
        {
            "table": "users",
            "column": "status",
            "owner_module": "auth",
            "concept": "account_lifecycle",
            "data_class": "MutableState",
            "allowed_tags": ["active", "suspended", "deleted"],
        },
        {
            "table": "user_risk_flags",
            "column": "risk_state",
            "owner_module": "risk",
            "concept": "risk_control",
            "data_class": "MutableState",
            "allowed_tags": ["clear", "risk_locked"],
        },
        {
            "table": "payment_intents",
            "column": "intent_state",
            "owner_module": "billing",
            "concept": "payment_intent_history",
            "data_class": "AppendOnlyFact",
            "allowed_tags": ["created", "submitted", "reconciled"],
        },
    ],
    "forbidden_imports": [
        ["risk", "auth"],
        ["risk", "billing"],
        ["billing", "auth"],
    ],
    "module_globs": {
        "auth": ["**/auth/**", "**/auth_*.py", "**/auth_*.ts"],
        "risk": ["**/risk/**", "**/risk_*.py", "**/risk_*.ts"],
        "billing": ["**/billing/**", "**/billing_*.py", "**/billing_*.ts"],
    },
}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="schema-gate",
        description="Fail-closed Schema-Boundary Contract Gate (G1-G5) for AI coding agents",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a starter schema-contract.json")
    p_init.add_argument("--output", default="schema-contract.json", help="Output JSON path")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing file")

    p_chk = sub.add_parser("check", help="Check files/dirs/git diff against contract (exit 0 PASS, 2 BLOCK)")
    p_chk.add_argument("--contract", default="schema-contract.json", help="Path to schema-contract.json")
    p_chk.add_argument("--module", help="Explicit module name override for all checked files")
    p_chk.add_argument("--staged", action="store_true", help="Check only git-staged files")
    p_chk.add_argument("--diff", dest="diff_base", help="Check files changed since git ref (e.g., origin/main)")
    p_chk.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_chk.add_argument("paths", nargs="*", help="Files or directories to scan (default: .)")

    p_hook = sub.add_parser("hook", help="Run AI coding agent hook adapter")
    hook_sub = p_hook.add_subparsers(dest="hook_target", required=True)
    p_cc = hook_sub.add_parser("claude-code", help="Claude Code PreToolUse/PostToolUse hook (reads JSON on stdin)")
    p_cc.add_argument("--contract", default="schema-contract.json", help="Path to schema-contract.json")
    p_cc.add_argument("--module", help="Optional explicit module override")

    p_mcp = sub.add_parser("mcp", help="Start zero-dependency JSON-RPC 2.0 MCP stdio server")
    p_mcp.add_argument("--contract", default="schema-contract.json", help="Path to schema-contract.json")

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.cmd == "init":
        out = Path(args.output)
        if out.exists() and not args.force:
            print(f"Refusing to overwrite existing {out} (pass --force to overwrite)", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(STARTER_CONTRACT, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"initialized": str(out), "contract_id": STARTER_CONTRACT["contract_id"]}))
        return 0

    if args.cmd == "mcp":
        SchemaGateMCPServer(args.contract).serve_stdio()
        return 0

    if args.cmd == "hook" and args.hook_target == "claude-code":
        code, msg = run_claude_code_hook(args.contract, module_override=args.module)
        if msg:
            print(msg, file=sys.stderr)
        return code

    if args.cmd == "check":
        contract = SchemaContract.from_json_file(args.contract)
        if args.staged or args.diff_base:
            targets = collect_git_changed_files(staged=args.staged, diff_base=args.diff_base)
        else:
            targets = args.paths or ["."]
        report = check_paths(targets, contract, module_name=args.module)
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        elif args.format == "sarif":
            print(json.dumps(report.to_sarif(), indent=2, ensure_ascii=False))
        else:
            print(report.format_text())
        return 0 if report.allowed else 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
