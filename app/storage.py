"""Transactional record of each scope decision, capture and associated observation."""
import os
from contextlib import contextmanager
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


@contextmanager
def connection():
    with psycopg.connect(os.environ.get("DATABASE_URL", ""), row_factory=dict_row,
                         connect_timeout=5) as db:
        yield db


def initialize():
    with connection() as db:
        db.execute("SELECT pg_advisory_xact_lock(17238657)")
        db.execute("""CREATE TABLE IF NOT EXISTS runs (
            id uuid PRIMARY KEY, started timestamptz NOT NULL DEFAULT now(),
            finished timestamptz, state text NOT NULL, details jsonb NOT NULL,
            evidence jsonb, finding jsonb,
            CHECK (finding IS NULL OR evidence IS NOT NULL))""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit (
            sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            run_id uuid REFERENCES runs(id), at timestamptz NOT NULL DEFAULT now(),
            decision text NOT NULL, reason text NOT NULL)""")


def begin(details, allowed, reason):
    run_id = uuid4()
    with connection() as db:
        db.execute("""INSERT INTO runs(id,state,details,finished)
                      VALUES (%s,%s,%s,CASE WHEN %s THEN NULL ELSE now() END)""",
                   (run_id, "capturing" if allowed else "blocked", Jsonb(details), allowed))
        log(db, run_id, "allowed" if allowed else "blocked", reason)
    return str(run_id)


def log(db, run_id, decision, reason):
    db.execute("INSERT INTO audit(run_id,decision,reason) VALUES (%s,%s,%s)",
               (run_id, decision, reason))


def finish(run_id, evidence=None, finding=None, error=None):
    state = "failed" if error else "complete"
    with connection() as db:
        updated = db.execute("""UPDATE runs SET state=%s, finished=now(), evidence=%s, finding=%s
                                WHERE id=%s AND state='capturing'""",
                             (state, Jsonb(evidence) if evidence else None,
                              Jsonb(finding) if finding else None, run_id))
        if updated.rowcount:
            log(db, run_id, state, error or "HTTP exchange committed")


def recover():
    # Compose runs one capture service. A restarted service owns its abandoned runs.
    with connection() as db:
        rows = db.execute("""UPDATE runs SET state='failed', finished=now()
                             WHERE state='capturing' RETURNING id""").fetchall()
        for row in rows:
            log(db, row["id"], "failed", "Capture process restarted before commit")


def overview():
    with connection() as db:
        totals = db.execute("""SELECT count(*) AS total, count(finding) AS findings,
                            count(*) FILTER (WHERE state='blocked') AS blocked FROM runs""").fetchone()
        runs = db.execute("""SELECT id,started,state,details,finding FROM runs
                             ORDER BY started DESC,id DESC LIMIT 100""").fetchall()
        audit = db.execute("SELECT * FROM audit ORDER BY sequence DESC LIMIT 100").fetchall()
    return dict(totals=totals, runs=runs, audit=audit)


def get_run(run_id):
    with connection() as db:
        row = db.execute("SELECT * FROM runs WHERE id=%s", (run_id,)).fetchone()
        if row:
            row["audit"] = db.execute("SELECT at,decision,reason FROM audit WHERE run_id=%s ORDER BY sequence",
                                      (run_id,)).fetchall()
        return row
