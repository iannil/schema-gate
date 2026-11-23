#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if command -v schema-gate >/dev/null 2>&1; then
  SG=(schema-gate)
else
  SG=(env PYTHONPATH=src python3 -m schema_gate.cli)
fi

TMPDIR_DEMO="$(mktemp -d -t schema-gate-demo-XXXXXX)"
trap 'rm -rf "$TMPDIR_DEMO"' EXIT
mkdir -p "$TMPDIR_DEMO/services/risk" "$TMPDIR_DEMO/services/billing"

echo "==> 1. AI coding agent writes a shortcut patch in Python (0 forbidden imports, silent shared-column overload)"
cat > "$TMPDIR_DEMO/services/risk/freeze.py" <<'EOF'
def freeze_high_risk_user(db, user_id):
    # Passes import linters, silently corrupts auth's users.status column:
    db.execute("UPDATE users SET status = 'risk_locked' WHERE id = :uid", {"uid": user_id})  # concept: risk_control
EOF

if "${SG[@]}" check --contract examples/schema-contract.json "$TMPDIR_DEMO/services/risk/freeze.py"; then
  echo "ERROR: SchemaGate unexpectedly allowed shared-column overload!" >&2
  exit 1
else
  echo "(Expected fail-closed BLOCK with G2/G3/G5 self-repair hints)"
fi

echo "==> 2. TypeScript / Prisma shortcut patch in risk service -> also BLOCKED"
cat > "$TMPDIR_DEMO/services/risk/freeze.ts" <<'EOF'
export async function freezeUser(prisma: any, id: string) {
  await prisma.user.update({ where: { id }, data: { status: "risk_locked" } });
}
EOF

if "${SG[@]}" check --contract examples/schema-contract.json "$TMPDIR_DEMO/services/risk/freeze.ts"; then
  echo "ERROR: SchemaGate unexpectedly allowed Prisma overload!" >&2
  exit 1
else
  echo "(Expected fail-closed BLOCK on Prisma mutation)"
fi

echo "==> 3. Billing service tries in-place UPDATE on AppendOnlyFact payment_intents -> BLOCKED by G4"
cat > "$TMPDIR_DEMO/services/billing/reconcile.py" <<'EOF'
def mark_reconciled(db, intent_id):
    db.execute("UPDATE payment_intents SET intent_state = 'reconciled' WHERE id = :id", {"id": intent_id})
EOF

if "${SG[@]}" check --contract examples/schema-contract.json "$TMPDIR_DEMO/services/billing/reconcile.py"; then
  echo "ERROR: SchemaGate unexpectedly allowed AppendOnlyFact overwrite!" >&2
  exit 1
else
  echo "(Expected fail-closed BLOCK on G4 AppendOnlyFact overwrite)"
fi

echo "==> 4. Concept-decompressed compliant patches (Python + TS + append-only INSERT) -> PASS"
cat > "$TMPDIR_DEMO/services/risk/freeze.py" <<'EOF'
def freeze_high_risk_user(db, user_id):
    db.execute("UPDATE user_risk_flags SET risk_state = 'risk_locked' WHERE user_id = :uid", {"uid": user_id})  # concept: risk_control
EOF
cat > "$TMPDIR_DEMO/services/risk/freeze.ts" <<'EOF'
export async function freezeUser(prisma: any, id: string) {
  await prisma.userRiskFlags.update({ where: { id }, data: { risk_state: "risk_locked" } });
}
EOF
cat > "$TMPDIR_DEMO/services/billing/reconcile.py" <<'EOF'
def mark_reconciled(db, intent_id):
    db.execute("INSERT INTO payment_intents (id, intent_state) VALUES (:id, 'reconciled')", {"id": intent_id})
EOF

"${SG[@]}" check --contract examples/schema-contract.json "$TMPDIR_DEMO/services"

echo "==> 5. Runtime SQLite proxy catches dynamically concatenated SQL at test time"
PYTHONPATH=src python3 - <<'PY'
import sqlite3
from schema_gate import SchemaBoundaryViolationError, SchemaContract, wrap_dbapi_connection

contract = SchemaContract.from_json_file("examples/schema-contract.json")
raw = sqlite3.connect(":memory:")
raw.execute("CREATE TABLE users (id INT, status TEXT)")
raw.execute("INSERT INTO users VALUES (1, 'active')")

guarded = wrap_dbapi_connection(raw, contract, module_name="risk")
tbl, col = "use" + "rs", "sta" + "tus"  # invisible to static scanners
try:
    guarded.execute(f"UPDATE {tbl} SET {col} = ? WHERE id = ?", ("risk_locked", 1))
    raise SystemExit("ERROR: runtime proxy missed dynamic SQL!")
except SchemaBoundaryViolationError as exc:
    print(f"Runtime proxy blocked dynamic SQL: {exc}")
PY

echo "==> Demo passed!"
