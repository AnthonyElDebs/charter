"""Transactional record of each scope decision, capture and associated observation."""
import os
from contextlib import contextmanager
from hashlib import sha256
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .findings import choose_finding


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
        db.execute("""CREATE TABLE IF NOT EXISTS campaigns (
            id uuid PRIMARY KEY, goal text NOT NULL,
            started timestamptz NOT NULL DEFAULT now(), finished timestamptz,
            state text NOT NULL, details jsonb NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS approvals (
            id uuid PRIMARY KEY, campaign_id uuid REFERENCES campaigns(id),
            created timestamptz NOT NULL DEFAULT now(), decided timestamptz,
            state text NOT NULL, task jsonb NOT NULL,
            CHECK (state IN ('pending', 'approved', 'denied')))""")


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
        campaigns = db.execute("""SELECT id, goal, state, started, finished, details FROM campaigns
                                  ORDER BY started DESC, id DESC LIMIT 20""").fetchall()
        approvals = db.execute("""SELECT id, campaign_id, created, task FROM approvals
                                  WHERE state='pending' ORDER BY created LIMIT 50""").fetchall()
    return dict(totals=totals, runs=runs, audit=audit, campaigns=campaigns, approvals=approvals)


def get_run(run_id):
    with connection() as db:
        row = db.execute("SELECT * FROM runs WHERE id=%s", (run_id,)).fetchone()
        if row:
            row["audit"] = db.execute("SELECT at,decision,reason FROM audit WHERE run_id=%s ORDER BY sequence",
                                      (run_id,)).fetchall()
        return row


def attach_finding(run_id, finding):
    if not isinstance(finding, dict) or not str(finding.get("title") or "").strip():
        return None
    try:
        run_id = str(UUID(str(run_id)))
    except (ValueError, AttributeError, TypeError):
        return None
    proposed = dict(finding)
    proposed["run_id"] = run_id
    with connection() as db:
        row = db.execute("SELECT evidence, finding FROM runs WHERE id=%s AND state='complete'",
                         (run_id,)).fetchone()
        if not row:
            return None
        chosen = choose_finding(row["finding"], proposed, row["evidence"])
        if chosen is None or chosen is row["finding"]:
            return None
        chosen = dict(chosen)
        chosen["run_id"] = run_id
        updated = db.execute("""UPDATE runs SET finding=%s
                                WHERE id=%s AND state='complete' AND evidence IS NOT NULL""",
                             (Jsonb(chosen), run_id))
        if not updated.rowcount:
            return None
        log(db, run_id, "finding", str(chosen["title"])[:240])
        return chosen


def note_block(campaign_id, url, reason, intent=""):
    details = {"url_sha256": sha256(str(url).encode("utf-8", "surrogatepass")).hexdigest()}
    if campaign_id:
        details["campaign_id"] = str(campaign_id)
    safe_intent = "".join(char for char in str(intent) if 32 <= ord(char) < 127)[:160]
    if safe_intent:
        details["intent"] = safe_intent
    return begin(details, False, str(reason)[:300])


def start_campaign(goal, details):
    campaign_id = uuid4()
    with connection() as db:
        db.execute("""INSERT INTO campaigns(id, goal, state, details) VALUES (%s, %s, 'running', %s)""",
                   (campaign_id, str(goal)[:2000], Jsonb(details or {})))
        log(db, None, "campaign", "started")
    return str(campaign_id)


def finish_campaign(campaign_id, state, extra):
    with connection() as db:
        row = db.execute("SELECT details FROM campaigns WHERE id=%s", (campaign_id,)).fetchone()
        if not row:
            return
        details = dict(row["details"] or {})
        details.update(extra or {})
        db.execute("""UPDATE campaigns SET state=%s, finished=now(), details=%s WHERE id=%s""",
                   (state, Jsonb(details), campaign_id))


def running_campaign():
    with connection() as db:
        return db.execute("""SELECT id FROM campaigns WHERE state='running'
                             ORDER BY started DESC LIMIT 1""").fetchone()


def get_campaign(campaign_id):
    with connection() as db:
        return db.execute("SELECT * FROM campaigns WHERE id=%s", (campaign_id,)).fetchone()


def campaign_runs(campaign_id):
    with connection() as db:
        return db.execute("""SELECT id, started, state, details, finding,
                                    (evidence IS NOT NULL) AS has_evidence
                             FROM runs WHERE details->>'campaign_id' = %s
                             ORDER BY started, id""", (str(campaign_id),)).fetchall()


def create_approval(campaign_id, task):
    approval_id = uuid4()
    with connection() as db:
        db.execute("""INSERT INTO approvals(id, campaign_id, state, task) VALUES (%s, %s, 'pending', %s)""",
                   (approval_id, campaign_id, Jsonb(task)))
    return str(approval_id)


def approval_state(approval_id):
    with connection() as db:
        row = db.execute("SELECT state FROM approvals WHERE id=%s", (approval_id,)).fetchone()
    return row["state"] if row else "denied"


def decide_approval(approval_id, state):
    if state not in {"approved", "denied"}:
        return False
    with connection() as db:
        updated = db.execute("""UPDATE approvals SET state=%s, decided=now()
                                WHERE id=%s AND state='pending'""", (state, approval_id))
    return bool(updated.rowcount)


def pending_approvals():
    with connection() as db:
        return db.execute("""SELECT id, campaign_id, created, task FROM approvals
                             WHERE state='pending' ORDER BY created""").fetchall()
