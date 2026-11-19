"""Closed loop: crawl, run the coverage matrix, then allow a few follow-ups."""
import logging
import os
from urllib.parse import urlsplit

from charter import Refused
from .access import run_access
from .approval import Queue
from .exchange import Client
from .exploit import run_exploit
from .framing import frame
from .governor import BudgetExhausted, Governor
from .llm import LlmError
from .findings import dedupe_findings
from .ledger import Ledger
from .narrative import write_report
from .pipeline import followup_cap, recon_cap, run_pipeline
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


def _note(observations, text):
    observations.append(frame(str(text)[:1500]))
    if len(observations) > 6:
        del observations[:-6]


def _explicit_url(task):
    url = task.get("url") if isinstance(task.get("url"), str) else ""
    if url.startswith(("http://", "https://")):
        return url
    return ""


def _repeat(ledger, task):
    """True when this task would redo recon or a check the matrix already ran."""
    if ledger is None:
        return False
    if task.get("worker") == "recon":
        return ledger.mapped or ledger.recon_turns >= recon_cap()
    ident = task.get("check") or task.get("worker")
    url = _explicit_url(task)
    if task.get("worker") == "http" and url:
        parts = urlsplit(url)
        place = f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path or '/'}"
        return ledger.attempted(place, "http")
    path = urlsplit(url).path or "/" if url else ""
    if path and ledger.attempted(path, ident):
        return True
    if not url and ledger.seen_check(ident):
        return True
    return False


def _crawl(client, findings, observations, lab, approval):
    ledger = client.ledger
    if ledger is None:
        return
    if not lab:
        decision = approval.require(client.campaign_id, {
            "worker": "recon", "intent": "Discover paths, forms, and parameters",
        })
        if decision != "approved":
            _note(observations, f"Operator {decision} reconnaissance.")
            return
    while ledger.recon_turns < recon_cap():
        if ledger.recon_turns and not ledger.pending():
            break
        task = {"worker": "recon", "intent": "Discover paths, forms, and parameters"}
        log.info("campaign %s worker recon", client.campaign_id)
        result = execute(task, client)
        ledger.recon_turns += 1
        ledger.mapped = True
        _remember(findings, result.findings)
        _note(observations, f"Recon pass {ledger.recon_turns} mapped {len(ledger.endpoints)} endpoints.")


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
            _note(observations, f"Operator {decision} the coverage matrix.")
            return
    log.info("campaign %s coverage matrix", client.campaign_id)
    result = run_pipeline(client)
    _remember(findings, result.findings)
    _note(observations, result.observation.split("\n", 1)[0][:500])


def _finish(findings, reason):
    return {"state": "proven" if _proven(findings) else "complete", "reason": reason}


def _accounts(supplied):
    primary = {key: supplied.get(key, "") for key in ("username", "password", "login_url")}
    accounts = []
    if primary["username"] and primary["password"]:
        accounts.append(dict(primary))
    second = supplied.get("second") if isinstance(supplied.get("second"), dict) else None
    if second and str(second.get("username") or "").strip() and second.get("password"):
        accounts.append({
            "username": str(second.get("username")).strip(),
            "password": second.get("password") or "",
            "login_url": str(second.get("login_url") or primary["login_url"] or "").strip(),
        })
    return accounts


def _drive(goal, charter, client, llm, governor, findings, observations, lab, approval, target):
    _crawl(client, findings, observations, lab, approval)
    _matrix(client, findings, observations, lab, approval)
    before = len(findings)
    run_access(client, findings)
    if len(findings) != before:
        findings[:] = dedupe_findings(findings)
    if llm is not None and client.ledger is not None and client.ledger.pipeline_done:
        _remember(findings, run_exploit(goal, client, findings, llm, governor, lab, approval))
        _note(observations, "Exploitation pass finished. Repeated coverage checks were not run.")
    if llm is None:
        return _finish(findings, "coverage matrix finished")
    planner = Planner(llm)
    followups = 0
    cap = followup_cap()
    while followups < cap:
        governor.before_turn()
        try:
            plan, tokens = planner.plan(goal, charter, observations, _digest(findings), governor.snapshot(),
                                        target, client.ledger.snapshot() if client.ledger else None)
        except PlanRejected as exc:
            governor.add_tokens(exc.tokens)
            _note(observations, "Planner output was rejected: " + str(exc) + ". Return one JSON object.")
            followups += 1
            continue
        governor.add_tokens(tokens)
        if plan.goal_proven and _proven(findings):
            return {"state": "proven", "reason": plan.summary}
        if plan.goal_proven and not plan.tasks:
            _note(observations, "goal_proven was ignored because no finding with proven=true is bound to captured HTTP evidence.")
            followups += 1
            continue
        if not plan.tasks:
            return _finish(findings, plan.summary)
        if plan.goal_proven:
            _note(observations, "goal_proven was ignored because no finding with proven=true is bound to captured HTTP evidence.")
        executed = False
        denied = False
        ran = 0
        for task in plan.tasks:
            if ran >= 2:
                break
            if _repeat(client.ledger, task):
                continue
            if not lab:
                decision = approval.require(client.campaign_id, task)
                if decision != "approved":
                    denied = True
                    _note(observations, f"Operator {decision} this step ({task['worker']}: {task['intent']}).")
                    continue
            log.info("campaign %s worker %s", client.campaign_id, task["worker"])
            result = execute(task, client)
            executed = True
            ran += 1
            if client.ledger is not None:
                if task.get("worker") == "recon":
                    client.ledger.recon_turns += 1
                    client.ledger.mapped = True
                ident = task.get("check") or task.get("worker")
                url = _explicit_url(task)
                if task.get("worker") == "http" and url:
                    parts = urlsplit(url)
                    place = f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path or '/'}"
                else:
                    place = (urlsplit(url).path or "/") if url else "/"
                outcome = "proven" if any(item.get("proven") for item in result.findings) else "checked"
                client.ledger.mark(place, ident, outcome)
            _remember(findings, result.findings)
            _note(observations, result.observation[:1500])
        if not executed:
            if denied:
                continue
            return _finish(findings, "coverage matrix finished; repeated recon and checks were not run")
        if plan.done:
            return _finish(findings, plan.summary)
        followups += 1
    return _finish(findings, "coverage matrix finished")


def credentials_from_env():
    primary = {"username": os.environ.get("CHARTER_AUTH_USER", "").strip(),
               "password": os.environ.get("CHARTER_AUTH_PASSWORD", ""),
               "login_url": os.environ.get("CHARTER_AUTH_LOGIN_URL", "").strip()}
    second_user = os.environ.get("CHARTER_AUTH_USER2", "").strip()
    second_password = os.environ.get("CHARTER_AUTH_PASSWORD2", "")
    if second_user and second_password:
        primary["second"] = {
            "username": second_user,
            "password": second_password,
            "login_url": os.environ.get("CHARTER_AUTH_LOGIN_URL2", "").strip() or primary["login_url"],
        }
    return primary


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
        client.accounts = _accounts(supplied)
        client.credentials = {key: supplied.get(key, "") for key in ("username", "password", "login_url")}
        probe = target or (charter.get("allow") or [""])[0]
        if probe:
            client.enforce(probe)
        elif target:
            raise Refused("no matching allow rule")
        outcome = _drive(goal, charter, client, llm, governor, findings, observations,
                         bool(lab), approval, target)
    except BudgetExhausted as exc:
        outcome = {"state": "proven" if _proven(findings) else "exhausted", "reason": str(exc)}
    except Refused as exc:
        outcome = {"state": "refused", "reason": str(exc)}
    except LlmError as exc:
        outcome = {"state": "proven" if _proven(findings) else "complete", "reason": str(exc)}
    finally:
        if client is not None:
            client.close()
        try:
            secrets = []
            if client is not None:
                secrets.extend(account.get("password") for account in client.accounts)
                secrets.append(client.credentials.get("password"))
                secrets.append(client.identity.get("token"))
                secrets.extend(getattr(client, "held_secrets", []))
            try:
                report = write_report(findings, llm, secrets)
            except Exception:
                report = write_report(findings, None, secrets)
            outcome["report"] = report
            store.finish_campaign(campaign_id, outcome["state"], {
                "reason": outcome.get("reason", ""),
                "requests": governor.requests,
                "turns": governor.turns,
                "tokens": governor.tokens,
                "findings": _digest(findings),
                "lab": bool(lab),
                "target": target or "",
                "recon_turns": client.ledger.recon_turns if client is not None and client.ledger is not None else 0,
                "report": report,
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

