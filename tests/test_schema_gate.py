"""Comprehensive unit & integration tests for schema-gate (G1-G5 across Python AST,
f-strings, SQLAlchemy, Django, TypeScript/Prisma/Drizzle, SQL migrations, runtime
DB-API SQL proxy, CLI, SARIF, Claude Code hook, and MCP stdio server)."""
from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from schema_gate.cli import main as cli_main
from schema_gate.contract import SchemaContract
from schema_gate.engine import check_paths, check_source
from schema_gate.hooks import evaluate_claude_code_payload, run_claude_code_hook
from schema_gate.mcp_server import SchemaGateMCPServer
from schema_gate.runtime_proxy import SchemaBoundaryViolationError, wrap_dbapi_connection


def _sample_contract() -> SchemaContract:
    return SchemaContract.from_dict({
        "contract_id": "test-ecommerce-v1",
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
            "auth": ["**/auth/**"],
            "risk": ["**/risk/**"],
            "billing": ["**/billing/**"],
        },
    })


class SchemaGateCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = _sample_contract()

    def test_python_g1_g2_g3_g5_silent_overload(self) -> None:
        bad = '''
def freeze(db, uid):
    db.execute("UPDATE users SET status = 'risk_locked' WHERE id = :id", {"id": uid})  # concept: risk_control
'''
        rep = check_source(bad, self.contract, module_name="risk", language="python")
        self.assertFalse(rep.allowed)
        codes = {v.code for v in rep.violations}
        self.assertIn("G3_FOREIGN_WRITER", codes)
        self.assertIn("G5_UNDECLARED_TAG", codes)
        self.assertIn("G2_CONCEPT_COMPRESSION", codes)
        self.assertNotIn("G1_FORBIDDEN_IMPORT", codes)

    def test_python_forbidden_import_g1(self) -> None:
        bad = "import auth\ndef f(): pass\n"
        rep = check_source(bad, self.contract, module_name="risk", language="python")
        self.assertFalse(rep.allowed)
        self.assertEqual([v.code for v in rep.violations], ["G1_FORBIDDEN_IMPORT"])

    def test_python_fstring_and_concat_sql(self) -> None:
        bad = '''
def patch(db, uid):
    tag = "risk_locked"
    q = "UPDATE users " + f"SET status = '{tag}' WHERE id = :id"
    db.execute(q)
'''
        rep = check_source(bad, self.contract, module_name="risk", language="python")
        self.assertFalse(rep.allowed)
        codes = {v.code for v in rep.violations}
        self.assertIn("G3_FOREIGN_WRITER", codes)
        self.assertIn("G5_UNDECLARED_TAG", codes)

    def test_python_sqlalchemy_and_django_orm(self) -> None:
        sa_bad = '''
def freeze(session, uid):
    stmt = update(Users).where(Users.id == uid).values(status="risk_locked")
    session.execute(stmt)
'''
        rep_sa = check_source(sa_bad, self.contract, module_name="risk", language="python")
        self.assertFalse(rep_sa.allowed)
        self.assertIn("G3_FOREIGN_WRITER", {v.code for v in rep_sa.violations})
        self.assertIn("G5_UNDECLARED_TAG", {v.code for v in rep_sa.violations})

        dj_bad = '''
def purge_history(intent_id):
    PaymentIntents.objects.filter(id=intent_id).delete()
'''
        rep_dj = check_source(dj_bad, self.contract, module_name="billing", language="python")
        self.assertFalse(rep_dj.allowed)
        self.assertIn("G4_APPEND_ONLY_OVERWRITE", {v.code for v in rep_dj.violations})

    def test_python_append_only_insert_passes_and_update_blocks(self) -> None:
        bad = '''
def reconcile(db, iid):
    db.execute("UPDATE payment_intents SET intent_state = 'reconciled' WHERE id = :id", {"id": iid})
'''
        rep_bad = check_source(bad, self.contract, module_name="billing", language="python")
        self.assertFalse(rep_bad.allowed)
        self.assertEqual([v.code for v in rep_bad.violations], ["G4_APPEND_ONLY_OVERWRITE"])

        good = '''
def reconcile(db, iid):
    db.execute("INSERT INTO payment_intents (id, intent_state) VALUES (:id, 'reconciled')", {"id": iid})
'''
        rep_good = check_source(good, self.contract, module_name="billing", language="python")
        self.assertTrue(rep_good.allowed, rep_good.format_text())

    def test_typescript_prisma_and_drizzle(self) -> None:
        prisma_bad = '''
import { something } from "../auth/service";
export async function freeze(prisma: any, id: string) {
  await prisma.user.update({
    where: { id },
    data: { status: "risk_locked" }
  });
}
'''
        rep = check_source(prisma_bad, self.contract, module_name="risk", language="typescript")
        self.assertFalse(rep.allowed)
        codes = {v.code for v in rep.violations}
        self.assertIn("G1_FORBIDDEN_IMPORT", codes)
        self.assertIn("G3_FOREIGN_WRITER", codes)
        self.assertIn("G5_UNDECLARED_TAG", codes)

        drizzle_bad = '''
export async function clearLedger(db: any) {
  await db.update(paymentIntents).set({ intentState: "reconciled" });
}
'''
        rep_dr = check_source(drizzle_bad, self.contract, module_name="billing", language="typescript")
        self.assertFalse(rep_dr.allowed)
        self.assertIn("G4_APPEND_ONLY_OVERWRITE", {v.code for v in rep_dr.violations})

        prisma_good = '''
export async function freeze(prisma: any, id: string) {
  await prisma.userRiskFlags.update({
    where: { id },
    data: { risk_state: "risk_locked" }
  });
}
'''
        rep_ok = check_source(prisma_good, self.contract, module_name="risk", language="typescript")
        self.assertTrue(rep_ok.allowed, rep_ok.format_text())

    def test_sql_migration_file(self) -> None:
        bad_sql = "DELETE FROM payment_intents WHERE intent_state = 'created';\n"
        rep = check_source(bad_sql, self.contract, module_name="billing", language="sql")
        self.assertFalse(rep.allowed)
        self.assertIn("G4_APPEND_ONLY_OVERWRITE", {v.code for v in rep.violations})

        drop_sql = "ALTER TABLE payment_intents DROP COLUMN intent_state;\n"
        rep_drop = check_source(drop_sql, self.contract, module_name="billing", language="sql")
        self.assertFalse(rep_drop.allowed)
        self.assertIn("G4_APPEND_ONLY_OVERWRITE", {v.code for v in rep_drop.violations})

    def test_runtime_sqlite_proxy_blocks_dynamic_sql(self) -> None:
        raw = sqlite3.connect(":memory:")
        raw.execute("CREATE TABLE users (id INT, status TEXT)")
        raw.execute("CREATE TABLE user_risk_flags (id INT, risk_state TEXT)")
        raw.execute("CREATE TABLE payment_intents (id INT, intent_state TEXT)")
        raw.execute("INSERT INTO users VALUES (1, 'active')")
        raw.execute("INSERT INTO user_risk_flags VALUES (1, 'clear')")
        raw.execute("INSERT INTO payment_intents VALUES (1, 'created')")

        risk_conn = wrap_dbapi_connection(raw, self.contract, module_name="risk")
        # Dynamic SQL built at runtime -> blocked before touching DB
        dyn_sql = "UPDATE " + "users" + " SET status = ? WHERE id = ?"
        with self.assertRaises(SchemaBoundaryViolationError) as ctx:
            risk_conn.execute(dyn_sql, ("risk_locked", 1))
        self.assertIn("G3_FOREIGN_WRITER", {v.code for v in ctx.exception.violations})
        # Verify row was NOT mutated
        self.assertEqual(raw.execute("SELECT status FROM users WHERE id = 1").fetchone()[0], "active")

        # Compliant owned write passes
        risk_conn.execute("UPDATE user_risk_flags SET risk_state = ? WHERE id = ?", ("risk_locked", 1))
        self.assertEqual(raw.execute("SELECT risk_state FROM user_risk_flags WHERE id = 1").fetchone()[0], "risk_locked")

        # Billing append-only overwrite blocked, append-only INSERT allowed
        bill_conn = wrap_dbapi_connection(raw, self.contract, module_name="billing")
        with self.assertRaises(SchemaBoundaryViolationError):
            bill_conn.execute("UPDATE payment_intents SET intent_state = 'reconciled' WHERE id = 1")
        bill_conn.execute("INSERT INTO payment_intents (id, intent_state) VALUES (2, 'reconciled')")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM payment_intents").fetchone()[0], 2)

    def test_claude_code_hook_cli_sarif_and_mcp_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            cpath = td_path / "schema-contract.json"
            self.assertEqual(cli_main(["init", "--output", str(cpath)]), 0)

            risk_file = td_path / "services" / "risk" / "handler.py"
            risk_file.parent.mkdir(parents=True, exist_ok=True)
            bad_code = 'def f(db, u):\n    db.execute("UPDATE users SET status = \'risk_locked\' WHERE id = :u")\n'
            risk_file.write_text(bad_code, encoding="utf-8")

            # CLI returns exit code 2 on violation
            self.assertEqual(cli_main(["check", "--contract", str(cpath), str(risk_file)]), 2)

            # SARIF export contains valid structure
            rep = check_paths([risk_file], SchemaContract.from_json_file(cpath))
            sarif = rep.to_sarif()
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 2)

            # Claude Code PreToolUse Write hook catches violation before write
            hook_payload = json.dumps({
                "tool_name": "Write",
                "tool_input": {"file_path": str(risk_file), "content": bad_code},
            })
            code, stderr_msg = run_claude_code_hook(cpath, raw_stdin=hook_payload)
            self.assertEqual(code, 2)
            self.assertIn("G3_FOREIGN_WRITER", stderr_msg)

            # Compliant edit passes hook
            good_code = 'def f(db, u):\n    db.execute("UPDATE user_risk_flags SET risk_state = \'risk_locked\' WHERE id = :u")\n'
            ok_payload = json.dumps({
                "tool_name": "Write",
                "tool_input": {"file_path": str(risk_file), "content": good_code},
            })
            code_ok, msg_ok = run_claude_code_hook(cpath, raw_stdin=ok_payload)
            self.assertEqual(code_ok, 0)
            self.assertEqual(msg_ok, "")

            # MCP server roundtrip
            srv = SchemaGateMCPServer(cpath)
            self.assertEqual(
                srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"]["serverInfo"]["name"],
                "schema-gate",
            )
            tools = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
            self.assertEqual(len(tools), 4)
            call_bad = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "schema_gate_check_patch",
                    "arguments": {"module": "risk", "source_code": bad_code, "language": "python"},
                },
            })
            payload_bad = json.loads(call_bad["result"]["content"][0]["text"])
            self.assertFalse(payload_bad["allowed"])

            call_sql = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "schema_gate_validate_sql",
                    "arguments": {"module": "billing", "sql": "INSERT INTO payment_intents (id, intent_state) VALUES (1, 'reconciled')"},
                },
            })
            payload_sql = json.loads(call_sql["result"]["content"][0]["text"])
            self.assertTrue(payload_sql["allowed"])


if __name__ == "__main__":
    unittest.main()
