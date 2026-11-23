# schema-gate

[![CI](https://github.com/iannil/schema-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/iannil/schema-gate/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/schema-gate.svg)](https://pypi.org/project/schema-gate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-brightgreen.svg)](pyproject.toml)

**Fail-Closed Schema-Boundary Contract Gate for AI Coding Agents**  
*(Zero-dependency Python 3 library, CLI, Claude Code Hook, MCP stdio server, SARIF CI gate & Runtime DB-API SQL Proxy)*

---

## Why `AGENTS.md` and Import Linters Are Not Enough

Your CI blocks `risk` from importing `auth`. Your `AGENTS.md` politely tells AI coding agents not to couple domains. Then an agent gets a sprint ticket *"freeze high-risk users"* and writes:

```sql
UPDATE users SET status = 'risk_locked' WHERE id = :entity_id
```

Zero forbidden imports. Unit tests pass. Yet this single line breaks three architectural invariants at once:
1. **Concept Compression (`G2`)** — stuffs fraud-risk state into `auth`'s account-lifecycle column;
2. **Foreign-Writer Coupling (`G3`)** — mutates a table column owned by another module behind its back;
3. **Domain Pollution (`G5`)** — injects an undeclared magic string `'risk_locked'` that silently breaks downstream `billing` / `fulfillment` switch statements.

Or an agent inside `billing` runs an in-place `UPDATE payment_intents SET intent_state = 'reconciled'` on an `AppendOnlyFact` audit table (**`G4`**), permanently erasing intent history so cross-system reconciliation becomes mathematically impossible.

In controlled live coding-agent trials (120 symmetric trials on the original 40-task suite), **both `AGENTS.md` soft rules and executable import linters allowed 73.33% (22/30)** of unsafe schema-boundary mutations. **SchemaGate** cut unsafe deliveries to **0.00% (0/30)** ($p = 4.77 \times 10^{-7}$), drove **100% (20/20) single-turn agent self-repair** via structured diagnostics, had **0/10 false blocks**, and ran in **~1.08 ms** at 4,096 contracted columns.

In a strictly disjoint **cross-vendor, multi-language external holdout** (5 unseen domains × Python & TypeScript/Prisma × **Claude Sonnet 5.5, Kimi K3, DeepSeek Chat** = 180 arm evaluations), `AGENTS.md` and import linters still let **62.22% (28/45)** of unsafe patches slip through (Claude 86.7%, Kimi 80.0%, DeepSeek 20.0%; Python 58.3%, TypeScript/Prisma 66.7%). **SchemaGate** cut unsafe deliveries to **0.00% (0/45)** ($p = 7.45 \times 10^{-9}$), achieved **100% (28/28) 1-turn auto-repair** across all three vendors and both languages, with **0/15 false blocks**.

---

## Five Enforced Invariants (`G1`–`G5`)

Formally verified in **Isabelle/HOL 2026** (session `RC_SchemaBoundary`, zero `sorry`):

| Gate | Invariant | What It Blocks |
|---|---|---|
| **G1** | Syntactic Import Compliance | Forbidden cross-module `import` / `require` edges |
| **G2** | Concept Decompression | Overloading one column with multiple domain concepts |
| **G3** | Single-Writer Ownership | Foreign modules writing to a column owned by another module |
| **G4** | Append-Only History Integrity | Destructive `UPDATE`, `DELETE`, `REPLACE`, or `DROP COLUMN` on `AppendOnlyFact` ledgers |
| **G5** | Domain Closure | Writing undeclared sentinel/magic tags outside a column's `allowed_tags` |

## Supported Languages & Surfaces

* **Python (`.py`)**: AST imports, raw & parameterized SQL (`:name`, `%(name)s`, `%s`, `?`, `$1`), f-strings / string concat, SQLAlchemy (`update(Table).values(...)`, `delete(Table)`, `query(Model).update(...)`), Django ORM (`Model.objects...update(...)`, `.delete()`), attribute/subscript writes (`user.status = ...`).
* **TypeScript / JavaScript (`.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`)**: ES/CJS imports, raw SQL strings & template literals, **Prisma** (`prisma.<model>.update/updateMany/upsert/delete/deleteMany`), **Drizzle** (`db.update(tbl).set(...)`, `db.delete(tbl)`).
* **SQL Migrations (`.sql`)**: `UPDATE`, `DELETE`, `REPLACE`, `INSERT`, `ALTER TABLE ... DROP COLUMN`.
* **Runtime DB-API 2.0 SQL Proxy**: `wrap_dbapi_connection(conn, contract, module_name)` intercepts dynamically constructed SQL at test/staging runtime using the exact same `schema-contract.json`.

---

## Installation

Zero third-party dependencies (Python 3.10+ stdlib only):

```bash
pip install schema-gate
```

Or from source:

```bash
pip install -e .
```

---

## Quickstart

### 1. CLI & CI Gate (Text / JSON / SARIF)

```bash
# Generate starter schema-contract.json
schema-gate init

# Check repository (exit 0 on PASS, exit 2 on BLOCK with repair hints)
schema-gate check --contract schema-contract.json src/

# Check only staged git files or PR diff against main
schema-gate check --contract schema-contract.json --staged
schema-gate check --contract schema-contract.json --diff origin/main --format sarif
```

Run the interactive multi-language + runtime-proxy demo:
```bash
bash examples/demo.sh
```

### 2. Claude Code `PreToolUse` Hook (1-Turn Auto-Repair)

Add to `.claude/settings.json` (see `examples/claude-code-settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "schema-gate hook claude-code --contract schema-contract.json"
          }
        ]
      }
    ]
  }
}
```

When Claude Code attempts a shortcut mutation, `schema-gate` exits `2` before disk write with exact rule codes and repair hints so the agent automatically decompresses the write into an owned column on the next turn.

### 3. MCP Stdio Server (Claude Code / Cursor / Any MCP Agent)

```json
{
  "mcpServers": {
    "schema-gate": {
      "command": "schema-gate",
      "args": ["mcp", "--contract", "schema-contract.json"]
    }
  }
}
```

Exposed MCP tools:
* `schema_gate_inspect_contract` — inspect table owners, concepts, append-only tables, and allowed enum tags before coding
* `schema_gate_check_patch` — dry-run check a Python / TypeScript / SQL patch against G1–G5
* `schema_gate_check_files` — scan files or directories
* `schema_gate_validate_sql` — check a raw SQL statement + parameters

### 4. Runtime SQL Proxy (Dynamic SQL Protection in Tests)

```python
import sqlite3
from schema_gate import SchemaContract, wrap_dbapi_connection

contract = SchemaContract.from_json_file("schema-contract.json")
conn = wrap_dbapi_connection(sqlite3.connect(":memory:"), contract, module_name="risk")
# Any dynamic SQL violating G2-G5 raises SchemaBoundaryViolationError before execution!
```

### 5. Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/iannil/schema-gate
    rev: v0.1.0
    hooks:
      - id: schema-gate
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Paper & Formal Proofs

* **Paper:** Tao Shi (Zhurong), *Data as the Boundary: Schema-Boundary Contract Gates Against Silent Semantic Coupling in AI Coding Agents*, https://zhurongshuo.com/en/papers/schema-boundary-gate/
* **Isabelle/HOL 2026 Proofs (`RC_SchemaBoundary`, zero `sorry`) & Benchmark Archive (Zenodo):** [10.5281/zenodo.24459632](https://doi.org/10.5281/zenodo.24459632)
