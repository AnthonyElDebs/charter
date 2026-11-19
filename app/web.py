"""Operator console. Choose an in-scope URL, capture it, or start a campaign."""
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
import threading
from urllib.parse import urlencode
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

from charter import Refused, check
from .capture import active_charter
from .exchange import request_through_proxy
from .llm import Llm, LlmError
from .loop import run_campaign
from .scope_gate import load_verified, local_charter, open_scope, restrictions_open
from . import storage
from .reports import templates, exchange_text, pdf


log = logging.getLogger("charter.web")
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


@asynccontextmanager
async def lifespan(app):
    storage.initialize()
    yield


app = FastAPI(title="Charter", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
ROOT = Path(os.environ.get("CHARTER_ROOT", "/run/charter"))


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                             "Referrer-Policy": "no-referrer",
                             "Content-Security-Policy": "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                                                        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response


def status():
    if restrictions_open():
        return {"active": True, "open": True, "local": True, "charter": open_scope("http://localhost/")}
    try:
        charter = load_verified(ROOT)
    except Exception:
        return {"active": False, "open": False, "charter": None, "local": False}
    return {"active": True, "open": False, "charter": charter, "local": local_charter(charter)}


def model_ready():
    return bool(os.environ.get("CHARTER_LLM_BASE_URL", "").strip()
                and os.environ.get("CHARTER_LLM_MODEL", "").strip())


def overview():
    return {**storage.overview(), "scope": status(), "model_ready": model_ready()}


def enforce_url(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise Refused("invalid URL characters")
    if restrictions_open():
        return open_scope(url)
    try:
        return check(active_charter(ROOT, url), {})
    except OSError as exc:
        raise Refused("missing or invalid approval bundle") from exc


async def form_fields(request):
    from urllib.parse import parse_qs
    raw = (await request.body()).decode("utf-8", "replace")
    return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}


def back(message, target=""):
    return RedirectResponse("/?" + urlencode({"message": message[:300], "target": target[:2048]}), status_code=303)


def page(request):
    data = overview()
    allow = ((data["scope"].get("charter") or {}).get("allow") or [])
    data["target"] = request.query_params.get("target") or (allow[0] if allow else "")
    data["message"] = request.query_params.get("message", "")
    data["unattended"] = bool(data["scope"].get("local"))
    return data


@app.get("/api/overview")
def overview_api():
    return overview()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.get_template("overview.html").render(**page(request))


@app.get("/style.css")
def css():
    return Response(Path(__file__).with_name("style.css").read_text(encoding="utf-8"), media_type="text/css")


@app.post("/actions/capture")
async def capture_action(request: Request):
    fields = await form_fields(request)
    url = fields.get("url", "").strip()
    method = fields.get("method", "GET").upper()
    if method not in METHODS:
        return back("Choose one of GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS.", url)
    body = "" if method in {"GET", "HEAD"} else fields.get("body", "")
    if len(body) > 262144:
        return back("The request body is too large.", url)
    try:
        enforce_url(url)
        response = request_through_proxy(url, method, body.encode() if body else None, intent="operator capture")
    except Refused as exc:
        return back(str(exc), url)
    except Exception as exc:
        log.warning("capture failed: %s", type(exc).__name__)
        return back("The capture proxy did not accept the request. Check that the lab is running.", url)
    run_id = response.headers.get("X-Charter-Run")
    if not run_id:
        return back("The capture proxy did not record this request.", url)
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@app.post("/actions/campaign")
async def campaign_action(request: Request):
    fields = await form_fields(request)
    url = fields.get("url", "").strip()
    goal = fields.get("goal", "").strip()
    if not goal:
        return back("Write the security goal to test.", url)
    try:
        charter = enforce_url(url)
        llm = Llm.from_env()
    except Refused as exc:
        return back(str(exc), url)
    except LlmError as exc:
        return back(str(exc), url)
    if storage.running_campaign():
        return back("A campaign is already running.", url)
    lab = restrictions_open() or fields.get("unattended") == "1"
    campaign_id = storage.start_campaign(goal, {"lab": lab, "target": url})
    threading.Thread(target=_campaign, args=(goal, llm, lab, url, campaign_id, charter), daemon=True).start()
    return RedirectResponse(f"/campaigns/{campaign_id}", status_code=303)


def _campaign(goal, llm, lab, url, campaign_id, charter):
    try:
        run_campaign(goal, root=ROOT, store=storage, llm=llm, lab=lab, charter=charter,
                     target=url, campaign_id=campaign_id)
    except Exception:
        log.exception("campaign failed")


@app.post("/actions/approvals/{approval_id}")
async def decide(approval_id: UUID, request: Request):
    fields = await form_fields(request)
    decision = fields.get("decision")
    if decision not in {"approved", "denied"}:
        return back("Choose approve or deny.")
    storage.decide_approval(str(approval_id), decision)
    return RedirectResponse("/", status_code=303)


@app.get("/api/runs/{run_id}")
def lookup(run_id: UUID):
    row = storage.get_run(run_id)
    if not row:
        raise HTTPException(404, "Unknown run")
    return row


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def detail(run_id: UUID):
    row = lookup(run_id)
    return templates.get_template("detail.html").render(run=row, exchange=exchange_text(row["evidence"] or {}))


@app.get("/api/campaigns/{campaign_id}")
def campaign_api(campaign_id: UUID):
    row = storage.get_campaign(campaign_id)
    if not row:
        raise HTTPException(404, "Unknown campaign")
    row = dict(row)
    row["runs"] = storage.campaign_runs(campaign_id)
    return row


@app.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_page(campaign_id: UUID):
    row = campaign_api(campaign_id)
    return templates.get_template("campaign.html").render(campaign=row)


@app.get("/runs/{run_id}/report.{extension}")
def report(run_id: UUID, extension: str):
    if extension not in {"pdf", "html"}:
        raise HTTPException(404)
    row = lookup(run_id)
    if row["state"] != "complete":
        raise HTTPException(409, "A report requires a completed capture")
    if extension == "pdf":
        body, mime = pdf(row), "application/pdf"
    else:
        body = templates.get_template("detail.html").render(
            run=row, exchange=exchange_text(row["evidence"]), exporting=True,
            css=Path(__file__).with_name("style.css").read_text(encoding="utf-8"))
        mime = "text/html"
    return Response(body, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="charter-{run_id}.{extension}"'})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
