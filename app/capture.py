"""A fail-closed HTTP capture service dedicated to the single local demonstration."""
import asyncio
from hashlib import sha256
import logging
from pathlib import Path
import re
from types import SimpleNamespace
from time import monotonic

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
from charter import check, Refused
from . import storage
from .evidence import assess, capture
from .worker_config import TARGET


def active_charter(root, url):
    current = (root / "current").read_text(encoding="ascii").strip()
    if not re.fullmatch("[a-f0-9]{32}", current):
        raise Refused("invalid charter reference")
    bundle = root / current
    return SimpleNamespace(url=url, charter=bundle / "charter.json", signature=bundle / "charter.json.sig",
                           authorization=bundle / "authorization.txt", signers=root / "signers")


class Gate:
    def __init__(self, root):
        self.root = root
        self.approved_clients = set()
        self.next_capture = 0.0

    def refuse(self, flow, reason, details):
        flow.response = http.Response.make(403, b"Blocked by Charter\n")
        run = storage.begin(details, False, reason)
        flow.response.headers["X-Charter-Run"] = run

    def http_connect(self, flow):
        self.refuse(flow, "Tunneling is outside the local lab charter", {})

    def requestheaders(self, flow):
        req = flow.request
        # Install a denial first. An addon exception must never default to forwarding.
        flow.response = http.Response.make(503, b"Capture unavailable\n")
        details = {"url_sha256": sha256(req.url.encode("utf-8", "surrogatepass")).hexdigest()}
        try:
            charter = check(active_charter(self.root, req.url), details)
            details["charter"] = charter
            if (req.url != TARGET or req.method != "GET" or req.host_header != "juice-shop:3000"
                    or req.headers.get("content-length", "0") != "0"
                    or any(k in req.headers for k in ("transfer-encoding", "upgrade", "authorization", "cookie"))):
                raise Refused("Only an anonymous GET of the lab landing page is supported")
            if monotonic() < self.next_capture:
                raise Refused("Local capture rate limit")
            run = storage.begin(details, True, "Signature, scope, test window and lab request verified")
        except (OSError, ValueError, TimeoutError) as exc:
            self.refuse(flow, str(exc) if isinstance(exc, Refused) else "Missing or invalid approval bundle", details)
            return
        self.next_capture = monotonic() + 1
        flow.metadata["charter_run"] = run
        self.approved_clients.add(flow.client_conn.id)
        # Construct the complete upstream header set. No client credentials or overrides are forwarded.
        req.headers = http.Headers(host="juice-shop:3000", accept="text/html",
                                   **{"accept-encoding": "identity", "user-agent": "Charter/1.0", "connection": "close"})
        flow.response = None

    def server_connect(self, data):
        if data.client.id not in self.approved_clients or data.server.address != ("juice-shop", 3000):
            data.server.error = "Unapproved upstream connection"

    def client_disconnected(self, client):
        self.approved_clients.discard(client.id)

    def response(self, flow):
        run = flow.metadata.get("charter_run")
        if run is None:
            return
        self.approved_clients.discard(flow.client_conn.id)
        try:
            evidence = capture(flow)
            storage.finish(run, evidence, assess(evidence))
        except Exception:
            logging.exception("Evidence commit failed")
            flow.response = http.Response.make(503, b"Could not commit evidence\n")
            storage.finish(run, error="Evidence commit failed")
            return
        flow.response.headers["X-Charter-Run"] = run

    def error(self, flow):
        self.approved_clients.discard(flow.client_conn.id)
        if run := flow.metadata.get("charter_run"):
            storage.finish(run, error="Upstream exchange failed before capture completed")


async def serve():
    storage.initialize()
    storage.recover()
    config = options.Options(listen_host="0.0.0.0", listen_port=8080, http2=False, rawtcp=False)
    server = DumpMaster(config, with_dumper=False)
    config.update(connection_strategy="lazy", upstream_cert=False, body_size_limit="2m")
    server.addons.add(Gate(Path("/run/charter")))
    await server.run()


if __name__ == "__main__":
    asyncio.run(serve())
