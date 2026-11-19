"""Fail-closed HTTP capture for whatever origin the signed charter allows.

Every request is checked against the current allow and deny rules. In-scope
exchanges are forwarded and stored. Tunnels to any other host are refused.
"""
import asyncio
from hashlib import sha256
import logging
import os
from pathlib import Path
import re
import socket
from types import SimpleNamespace
from time import monotonic
from urllib.parse import urlsplit

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
from charter import check, Refused
from . import storage
from .evidence import assess, capture


METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
FORWARDED = ("accept", "content-type", "authorization", "cookie")


def active_charter(root, url):
    current = (root / "current").read_text(encoding="ascii").strip()
    if not re.fullmatch("[a-f0-9]{32}", current):
        raise Refused("invalid charter reference")
    bundle = root / current
    return SimpleNamespace(url=url, charter=bundle / "charter.json", signature=bundle / "charter.json.sig",
                           authorization=bundle / "authorization.txt", signers=root / "signers")


def _interval():
    try:
        value = float(os.environ.get("CHARTER_MIN_INTERVAL", "1"))
    except ValueError:
        return 1.0
    return value if value >= 0 else 1.0


def reason_code(reason):
    return "rate-limit" if "rate limit" in reason else "denied"


def copy_header(value):
    text = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise Refused("invalid header value")
    return text[:4096]


def upstream_of(url):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    default = 443 if parts.scheme == "https" else 80
    visible = parts.hostname if port == default else f"{parts.hostname}:{port}"
    return visible, (parts.hostname, port)


def same_upstream(expected, address):
    if not address or len(address) < 2 or address[1] != expected[1]:
        return False
    host = address[0]
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if host == expected[0]:
        return True
    try:
        infos = socket.getaddrinfo(expected[0], expected[1], type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    return any(item[4][0] == host for item in infos)


def origin_permitted(root, host, port):
    """Allow a TLS tunnel only when the signed charter names this host and port."""
    from .scope_gate import load_verified
    charter = load_verified(root)
    for rule in charter["allow"]:
        parts = urlsplit(rule)
        rule_port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.hostname == host and rule_port == port:
            return charter
    raise Refused("no matching allow rule")


def forwarded_headers(req, host):
    fields = [(b"host", host.encode("ascii")), (b"accept-encoding", b"identity"),
              (b"user-agent", b"Charter/1.0"), (b"connection", b"close")]
    saw_accept = False
    for name in FORWARDED:
        if name in req.headers:
            fields.append((name.encode("ascii"), copy_header(req.headers[name]).encode("latin-1")))
            saw_accept = saw_accept or name == "accept"
    if not saw_accept:
        fields.append((b"accept", b"*/*"))
    return http.Headers(fields)


class Gate:
    def __init__(self, root):
        self.root = root
        self.approved_clients = {}
        self.next_capture = 0.0
        self.min_interval = _interval()

    def refuse(self, flow, reason, details):
        flow.response = http.Response.make(403, b"Blocked by Charter\n")
        run = storage.begin(details, False, reason)
        flow.response.headers["X-Charter-Run"] = run
        flow.response.headers["X-Charter-Reason"] = reason_code(reason)

    def http_connect(self, flow):
        from .scope_gate import restrictions_open
        host, port = flow.request.host, flow.request.port or 443
        synthetic = f"https://{host}:{port}/"
        details = {"url_sha256": sha256(synthetic.encode("utf-8", "surrogatepass")).hexdigest()}
        flow.response = http.Response.make(403, b"Blocked by Charter\n")
        try:
            if not restrictions_open():
                origin_permitted(self.root, host, port)
        except (OSError, ValueError, TimeoutError) as exc:
            self.refuse(flow, str(exc) if isinstance(exc, Refused) else "Missing or invalid approval bundle", details)
            return
        self.approved_clients[flow.client_conn.id] = (host, port)
        flow.response = None

    def requestheaders(self, flow):
        req = flow.request
        # Install a denial first. An addon exception must never default to forwarding.
        flow.response = http.Response.make(503, b"Capture unavailable\n")
        details = {"url_sha256": sha256(req.url.encode("utf-8", "surrogatepass")).hexdigest()}
        try:
            from .scope_gate import open_scope, restrictions_open
            if restrictions_open():
                charter = open_scope(req.url)
            else:
                charter = check(active_charter(self.root, req.url), details)
            details["charter"] = charter
            if req.method.upper() not in METHODS:
                raise Refused("method is outside the signed charter")
            if any(name in req.headers for name in ("transfer-encoding", "upgrade", "proxy-authorization", "proxy-connection")):
                raise Refused("unsupported hop-by-hop header")
            try:
                length = int(req.headers.get("content-length", "0") or "0")
            except ValueError as exc:
                raise Refused("invalid content length") from exc
            if length < 0 or length > 1_000_000:
                raise Refused("request body exceeds the local limit")
            campaign = req.headers.get("x-charter-campaign", "")
            if campaign:
                if not re.fullmatch(r"[0-9a-fA-F-]{36}", campaign):
                    raise Refused("invalid campaign id")
                details["campaign_id"] = campaign.lower()
            intent = "".join(char for char in req.headers.get("x-charter-intent", "") if 32 <= ord(char) < 127)[:160]
            if intent:
                details["intent"] = intent
            if not restrictions_open() and self.min_interval and monotonic() < self.next_capture:
                raise Refused("Local capture rate limit")
            host, upstream = upstream_of(req.url)
            run = storage.begin(details, True, "Signature, scope and test window verified")
        except (OSError, ValueError, TimeoutError) as exc:
            self.approved_clients.pop(flow.client_conn.id, None)
            self.refuse(flow, str(exc) if isinstance(exc, Refused) else "Missing or invalid approval bundle", details)
            return
        self.next_capture = monotonic() + self.min_interval
        flow.metadata["charter_run"] = run
        self.approved_clients[flow.client_conn.id] = upstream
        # The host is taken from the URL that passed the charter. Campaign metadata stays local.
        req.headers = forwarded_headers(req, host)
        flow.response = None

    def server_connect(self, data):
        expected = self.approved_clients.get(data.client.id)
        if expected is None or not same_upstream(expected, data.server.address):
            data.server.error = "Unapproved upstream connection"

    def client_disconnected(self, client):
        self.approved_clients.pop(client.id, None)

    def response(self, flow):
        run = flow.metadata.get("charter_run")
        if run is None:
            return
        self.approved_clients.pop(flow.client_conn.id, None)
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
        self.approved_clients.pop(flow.client_conn.id, None)
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
