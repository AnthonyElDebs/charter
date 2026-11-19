"""Closed loop: plan, dispatch, record evidence, and plan again."""
import logging
import os

from charter import Refused
from .approval import Queue
from .exchange import Client
from .framing import frame
from .governor import BudgetExhausted, Governor
from .llm import LlmError
from .findings import dedupe_findings
from .ledger import Ledger
from .pipeline import recon_cap, run_pipeline
from .planner import PlanRejected, Planner
from .scope_gate import load_verified, local_charter, open_scope, restrictions_open
from .workers import execute


log = logging.getLogger("charter.campaign")


class CampaignResult:
    def __init__(self, campaign_id, state, findings, reason=""):
        self.campaign_id = campaign_id
        self.state = state
        self.findings = list(findings)
        self.reason = reason


def resolve_lab_mode(explicit, charter):
    """Lab mode skips per-step approval. The charter is still enforced on every request."""
    if explicit is not None:
        return bool(explicit)
    env = os.environ.get("CHARTER_LAB_MODE")
    if env is not None and env.strip() != "":
        return env.strip().lower() in {"1", "true", "yes"}
    return local_charter(charter)


def _digest(findings):
    return [{"title": item["title"], "severity": item["severity"], "proven": bool(item.get("proven")),
             "run_id": item.get("run_id"), "check": item.get("check", "")} for item in findings]


def _proven(findings):
    return any(item.get("proven") and item.get("run_id") for item in findings)


def _remember(findings, extra):
    findings.extend(extra)
    findings[:] = dedupe_findings(findings)


def _matrix(client, findings, observations, lab, approval):
    ledger = client.ledger
    if ledger is None or ledger.pipeline_done or not ledger.mapped:
        return
    if not lab:
        decision = approval.require(client.campaign_id, {
            "worker": "coverage", "check": "sweep",
            "intent": "run the coverage matrix on endpoints already discovered",
        })
        if decision != "approved":
            ledger.pipeline_done = True
            observations.append(frame(f"Operator {decision} the coverage matrix."))
            return
    result = run_pipeline(client)
    _remember(findings, result.findings)
    observations.append(frame(result.observation.split("\n", 1)[0][:500]))


def _drive(goal, charter, client, planner, governor, findings, observations, lab, approval, target):
    while True:
        governor.before_turn()
        try:
            plan, tokens = planner.plan(goal, charter, observations, _digest(findings), governor.snapshot(),
                                        target, client.ledger.snapshot() if client.ledger else None)
        except PlanRejected as exc:
            governor.add_tokens(exc.tokens)
            observations.append(frame("Planner output was rejected: " + str(exc) + ". Return one JSON object."))
            continue
        governor.add_tokens(tokens)
        if plan.goal_proven and _proven(findings):
            return {"state": "proven", "reason": plan.summary}
        if plan.goal_proven and not plan.tasks:
            observations.append(frame(
                "goal_proven was ignored because no finding with proven=true is bound to captured HTTP evidence."
            ))
            continue
        if not plan.tasks:
            return {"state": "proven" if _proven(findings) else "complete", "reason": plan.summary}
        if plan.goal_proven:
            observations.append(frame(
                "goal_proven was ignored because no finding with proven=true is bound to captured HTTP evidence."
            ))
        executed = False
        skipped_recon = False
        for task in plan.tasks:
            if task["worker"] == "recon" and client.ledger is not None and (
                    client.ledger.mapped or client.ledger.recon_turns >= recon_cap()):
                skipped_recon = True
                observations.append(frame("Recon was not repeated. The ledger already lists the site structure."))
                continue
            if not lab:
                decision = approval.require(client.campaign_id, task)
                if decision != "approved":
                    observations.append(frame(
                        f"Operator {decision} this step ({task['worker']}: {task['intent']})."
                    ))
                    continue
            log.info("campaign %s worker %s", client.campaign_id, task["worker"])
            result = execute(task, client)
            executed = True
            if task["worker"] == "recon" and client.ledger is not None:
                client.ledger.recon_turns += 1
                client.ledger.mapped = True
            _remember(findings, result.findings)
            observations.append(frame(result.observation))
        if client.ledger is not None and client.ledger.mapped:
            _matrix(client, findings, observations, lab, approval)
        if len(observations) > 8:
            del observations[:-8]
        if skipped_recon and not executed and client.ledger is not None and client.ledger.pipeline_done:
            return {"state": "proven" if _proven(findings) else "complete",
                    "reason": "coverage matrix finished; repeated recon was not run"}
        if plan.done:
            return {"state": "proven" if _proven(findings) else "complete", "reason": plan.summary}


def credentials_from_env():
    return {"username": os.environ.get("CHARTER_AUTH_USER", "").strip(),
            "password": os.environ.get("CHARTER_AUTH_PASSWORD", ""),
            "login_url": os.environ.get("CHARTER_AUTH_LOGIN_URL", "").strip()}


def run_campaign(goal, *, root, store, llm, lab=None, governor=None, approval=None, transport=None,
                 proxy=None, target=None, campaign_id=None, charter=None, credentials=None):
    if charter is None:
        charter = open_scope(target or "http://localhost/") if restrictions_open() else load_verified(root)
    governor = governor or Governor.from_env()
    if restrictions_open():
        lab = True
    elif lab is None:
        lab = resolve_lab_mode(None, charter)
    if not lab and approval is None:
        timeout = int(os.environ.get("CHARTER_APPROVAL_TIMEOUT", "3600") or "3600")
        approval = Queue(store, timeout=max(1, timeout))
    findings, observations = [], []
    outcome = {"state": "exhausted", "reason": "stopped"}
    if campaign_id is None:
        campaign_id = store.start_campaign(goal, {"lab": bool(lab), "target": target or ""})
    client = None
    try:
        client = Client(root=root, charter=charter, store=store, governor=governor, proxy=proxy,
                        transport=transport, campaign_id=campaign_id, target=target)
        client.ledger = Ledger()
        supplied = credentials if credentials is not None else credentials_from_env()
        client.credentials = {key: supplied.get(key, "") for key in ("username", "password", "login_url")}
        probe = target or (charter.get("allow") or [""])[0]
        if probe:
            client.enforce(probe)
        elif target:
            raise Refused("no matching allow rule")
        outcome = _drive(goal, charter, client, Planner(llm), governor, findings, observations,
                         bool(lab), approval, target)
    except BudgetExhausted as exc:
        outcome = {"state": "proven" if _proven(findings) else "exhausted", "reason": str(exc)}
    except Refused as exc:
        outcome = {"state": "refused", "reason": str(exc)}
    except LlmError as exc:
        outcome = {"state": "exhausted", "reason": str(exc)}
    finally:
        if client is not None:
            client.close()
        try:
            store.finish_campaign(campaign_id, outcome["state"], {
                "reason": outcome.get("reason", ""),
                "requests": governor.requests,
                "turns": governor.turns,
                "tokens": governor.tokens,
                "findings": _digest(findings),
                "lab": bool(lab),
                "target": target or "",
            })
        except Exception:
            logging.exception("could not finish campaign")
    return CampaignResult(campaign_id, outcome["state"], findings, outcome.get("reason", ""))


def default_target(root, fallback):
    chosen = os.environ.get("CHARTER_TARGET", "").strip()
    if chosen:
        return chosen
    try:
        charter = load_verified(root)
    except Exception:
        return fallback
    allow = charter.get("allow") or []
    return allow[0] if allow else fallback

