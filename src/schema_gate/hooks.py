"""Claude Code & Cursor hook integration for fail-closed SchemaGate enforcement.

Supports Claude Code `PreToolUse` and `PostToolUse` hook JSON payloads on stdin:
  - Inspects `Write`, `Edit`, and `MultiEdit` tool inputs before/after disk write.
  - Exits 0 on pass; exits 2 with structured self-repair diagnostics on stderr on violation
    so the coding agent immediately decompresses the concept or fixes ownership in 1 turn.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import sys

from .contract import CheckReport, SchemaContract
from .engine import SUPPORTED_EXTENSIONS, _language_for_path, check_file, check_source


def evaluate_claude_code_payload(
    payload: dict[str, Any],
    contract: SchemaContract,
    *,
    module_override: str | None = None,
) -> CheckReport:
    tool_name = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input") or {}

    file_path_str = str(tool_input.get("file_path") or tool_input.get("path") or "")
    if not file_path_str:
        return CheckReport(allowed=True, files_checked=0, contract_id=contract.contract_id)

    p = Path(file_path_str)
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return CheckReport(allowed=True, files_checked=0, contract_id=contract.contract_id)

    lang = _language_for_path(p)
    assert lang is not None
    mod = module_override or contract.infer_module_for_path(p) or p.stem

    # PreToolUse `Write` provides full proposed `content` directly before disk write
    if tool_name == "Write" and isinstance(tool_input.get("content"), str):
        return check_source(
            tool_input["content"],
            contract,
            module_name=mod,
            language=lang,
            file_path=file_path_str,
        )

    # PreToolUse `Edit` / `MultiEdit`: simulate patch on current file contents when present
    if tool_name == "Edit" and p.exists():
        old_s = tool_input.get("old_string")
        new_s = tool_input.get("new_string")
        if isinstance(old_s, str) and isinstance(new_s, str):
            current = p.read_text(encoding="utf-8")
            proposed = current.replace(old_s, new_s, 1) if old_s in current else current
            return check_source(proposed, contract, module_name=mod, language=lang, file_path=file_path_str)

    if tool_name == "MultiEdit" and p.exists() and isinstance(tool_input.get("edits"), list):
        proposed = p.read_text(encoding="utf-8")
        for ed in tool_input["edits"]:
            old_s = ed.get("old_string")
            new_s = ed.get("new_string")
            if isinstance(old_s, str) and isinstance(new_s, str) and old_s in proposed:
                proposed = proposed.replace(old_s, new_s, 1)
        return check_source(proposed, contract, module_name=mod, language=lang, file_path=file_path_str)

    # PostToolUse or fallback: inspect file on disk
    if p.exists():
        return check_file(p, contract, module_name=mod)

    return CheckReport(allowed=True, files_checked=0, contract_id=contract.contract_id)


def run_claude_code_hook(
    contract_path: str | Path,
    raw_stdin: str | None = None,
    *,
    module_override: str | None = None,
) -> tuple[int, str]:
    contract = SchemaContract.from_json_file(contract_path)
    text = raw_stdin if raw_stdin is not None else sys.stdin.read()
    if not text.strip():
        return 0, ""
    payload = json.loads(text)
    report = evaluate_claude_code_payload(payload, contract, module_override=module_override)
    if report.allowed:
        return 0, ""
    return 2, report.format_text()
