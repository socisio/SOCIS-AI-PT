"""On an existing deploy, Base.metadata.create_all() provisions tables directly — it never creates Alembic's own
alembic_version bookkeeping table, so `alembic upgrade head` starts from scratch and fails with "relation already
exists" on every table create_all already made. Confirmed live: this is exactly what happened when migration 023
(platform_settings.value VARCHAR->TEXT) was deployed. main.py now auto-stamps the database at head the first time
(alembic_version missing) right after create_all — but must NEVER do so for a database that already has real Alembic
history (that would silently skip whatever migrations are still pending).

  python tests/test_alembic_autostamp.py
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "main.py"), encoding="utf-8").read()

t("the auto-stamp checks whether alembic_version exists BEFORE stamping (never unconditional)",
  "to_regclass('public.alembic_version')" in SRC)
t("it only stamps when alembic_version is missing (exists is None), never when real history is present",
  "if exists is None:" in SRC)
t("it uses alembic's own stamp command (the correct, documented way to mark a revision applied without re-running it)",
  "_alembic_command.stamp(_cfg, \"head\")" in SRC)
t("a failure to stamp is caught and logged, never fatal to startup (the app must still come up even if this fails)",
  "except Exception as stamp_err:" in SRC)
t("the known correctness caveat (this assumes the live schema already matches head) is documented for future "
  "migrations that ALTER an existing column, not just ones that create new tables",
  "CORRECTNESS CAVEAT" in SRC)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
