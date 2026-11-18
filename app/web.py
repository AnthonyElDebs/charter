from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

from charter import check
from .capture import active_charter
from . import storage
from .reports import templates, exchange_text, pdf
from .worker_config import TARGET


@asynccontextmanager
async def lifespan(app):
    storage.initialize()
    yield


app = FastAPI(title="Charter", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
ROOT = Path("/run/charter")


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                             "Referrer-Policy": "no-referrer",
                             "Content-Security-Policy": "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                                                        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
    return response


def status():
    try:
        charter = check(active_charter(ROOT, TARGET), {})
    except Exception:
        return {"active": False}
    return {"active": True, "charter": charter}


@app.get("/api/overview")
def overview():
    return {**storage.overview(), "scope": status()}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return templates.get_template("overview.html").render(**overview())


@app.get("/style.css")
def css():
    return Response(Path(__file__).with_name("style.css").read_text(encoding="utf-8"), media_type="text/css")


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
