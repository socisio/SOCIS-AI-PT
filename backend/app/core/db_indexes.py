"""Create the database indexes that the list/detail queries rely on (idempotent, never blocks startup).

PostgreSQL does NOT index foreign-key columns automatically, and the models did not declare indexes for them. Every list
page, every eager child load (`WHERE scan_id IN (...)`) and every owner filter therefore scanned whole tables, which gets
slower with every scan you run. `create_all()` only creates missing TABLES, so existing databases never got indexes either.

The planning is a pure function (unit-tested); the runner executes it in the background after startup.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Iterable, List, Set, Tuple

logger = logging.getLogger(__name__)

# (table, candidate columns). An index is created for each candidate column that exists and is not already the leading
# column of an existing index. (Some child tables name the parent column `vuln_id`, others `vulnerability_id`.)
WANTED: List[Tuple[str, List[str]]] = [
    ("vulnerabilities", ["scan_id", "severity", "status", "created_at", "assigned_to"]),
    ("scans", ["project_id", "status", "created_at"]),
    ("projects", ["owner_id", "created_at"]),
    ("scan_tool_results", ["scan_id"]),
    ("ai_analyses", ["scan_id"]),
    ("reports", ["scan_id"]),
    ("fixes", ["vulnerability_id", "vuln_id"]),
    ("exploits", ["vulnerability_id", "vuln_id"]),
    ("vuln_comments", ["vulnerability_id", "vuln_id"]),
    ("audit_logs", ["user_id"]),
]
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def _already_indexed(table: str, column: str, indexdefs: Iterable[Tuple[str, str]]) -> bool:
    """True if some existing index on `table` starts with `column` (a leading-column match is what makes it usable)."""
    pat = re.compile(r"\(\s*\"?%s\"?\s*[,)\s]" % re.escape(column))
    return any(t == table and pat.search(d.split(" USING ", 1)[-1]) for t, d in indexdefs)


def plan_index_statements(columns_by_table: Dict[str, Set[str]], indexdefs: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Return [(index_name, CREATE INDEX statement)] for every wanted index that is missing.

    columns_by_table: {table: {existing columns}}; indexdefs: [(table, pg_indexes.indexdef)].
    """
    indexdefs = list(indexdefs)
    out: List[Tuple[str, str]] = []
    for table, candidates in WANTED:
        have = columns_by_table.get(table)
        if not have:
            continue                                   # table does not exist (yet)
        for col in candidates:
            if col not in have or _already_indexed(table, col, indexdefs):
                continue
            name = f"ix_perf_{table}_{col}"
            if not (_IDENT.match(table) and _IDENT.match(col) and _IDENT.match(name)):
                continue                               # constants today; guards against a bad edit
            out.append((name, f'CREATE INDEX IF NOT EXISTS {name} ON "{table}" ("{col}")'))
    return out


async def ensure_performance_indexes(session_factory) -> List[str]:
    """Create any missing indexes. Never raises: a failure only means the app stays as slow as before."""
    from sqlalchemy import bindparam, text
    created: List[str] = []
    try:
        wanted_tables = [t for t, _ in WANTED]                      # constants, sent as bound parameters
        async with session_factory() as db:
            cols = (await db.execute(
                text("SELECT table_name, column_name FROM information_schema.columns "
                     "WHERE table_schema = 'public' AND table_name IN :tables")
                .bindparams(bindparam("tables", expanding=True)),
                {"tables": wanted_tables})).all()
            idx = (await db.execute(text(
                "SELECT tablename, indexdef FROM pg_indexes WHERE schemaname = 'public'"))).all()
        by_table: Dict[str, Set[str]] = {}
        for t, c in cols:
            by_table.setdefault(t, set()).add(c)
        for name, stmt in plan_index_statements(by_table, [(t, d) for t, d in idx]):
            try:
                async with session_factory() as db:
                    await db.execute(text(stmt))
                    await db.commit()
                created.append(name)
            except Exception as exc:                                  # one bad index must not stop the others
                logger.warning("Could not create index %s: %s", name, exc)
        if created:
            logger.info("Performance indexes created: %s", ", ".join(created))
        else:
            logger.info("Performance indexes already in place")
    except Exception as exc:
        logger.warning("Performance index check skipped: %s", exc)
    return created
