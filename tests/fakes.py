"""In-memory origin and campaign store for campaign tests. Not collected as a test module."""
import json
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx

from app.findings import choose_finding


class MemoryStore:
    def __init__(self):
        self.runs = {}
        self.campaigns = {}
        self.blocks = []
        self.approvals = {}

    def start_campaign(self, goal, details):
        campaign_id = str(uuid4())
        self.campaigns[campaign_id] = {"state": "running", "details": dict(details or {})}
        return campaign_id

    def finish_campaign(self, campaign_id, state, extra):
        row = self.campaigns.setdefault(campaign_id, {})
        row["state"] = state
        row["extra"] = extra

    def add_run(self, run_id, evidence):
        self.runs[str(run_id)] = {"state": "complete", "evidence": evidence, "finding": None}

    def attach_finding(self, run_id, finding):
        row = self.runs.get(str(run_id))
        if not row or row["state"] != "complete" or not row["evidence"]:
            return None
        chosen = choose_finding(row["finding"], finding, row["evidence"])
        if not chosen or chosen is row["finding"]:
            return None
        chosen = dict(chosen)
        chosen["run_id"] = str(run_id)
        row["finding"] = chosen
        return chosen

    def note_block(self, campaign_id, url, reason, intent=""):
        self.blocks.append((campaign_id, str(url), str(reason), intent))
        return "blocked"

    def create_approval(self, campaign_id, task):
        approval_id = str(uuid4())
        self.approvals[approval_id] = "pending"
        return approval_id

    def approval_state(self, approval_id):
        return self.approvals.get(approval_id, "denied")

    def decide_approval(self, approval_id, state):
        if approval_id not in self.approvals:
            return False
        self.approvals[approval_id] = state
        return True


class Shop:
    """Small stand-in for the lab API and for an unauthenticated secret page."""

    def __init__(self, store):
        self.store = store
        self.urls = []
        self.secrets = []
        self.users = [{"id": 1, "email": "admin@juice-sh.op", "role": "admin", "password": "admin-secret", "basket": 1}]
        self.next_id = 2

    def transport(self):
        return httpx.MockTransport(self.handle)

    def handle(self, request):
        self.urls.append(str(request.url))
        path = urlsplit(str(request.url)).path
        path = "/" if path in {"", "/"} else path.rstrip("/")
        if path == "/":
            body = "<html><a href=\"http://evil.example/steal\">x</a><a href=\"/admin/users.html\">users</a></html>"
            return self._send(200, body, "text/html")
        if path == "/rest/products":
            return self._send(200, {"data": [{"id": 1, "name": "apple"}]})
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\n", "text/plain")
        if path == "/api-docs":
            return self._send(200, "<html>docs</html>", "text/html")
        if path == "/ftp":
            return self._send(200, "<html><a href=\"/rest/products\">files</a></html>", "text/html")
        if path == "/metrics":
            return self._send(200, "http_requests_total 1\n", "text/plain")
        if path == "/encryptionkeys":
            return self._send(200, "keys\n", "text/plain")
        if path == "/api/SecurityQuestions":
            return self._send(200, {"data": [{"id": 1, "question": "pet"}]})
        if path == "/rest/admin/application-configuration":
            return self._send(200, {"config": "open"})
        if path == "/rest/products/search":
            query = parse_qs(urlsplit(str(request.url)).query).get("q", [""])[0]
            rows = [{"id": 1}, {"id": 2}] if "OR(1=1)" in query else []
            return self._send(200, {"data": rows})
        if path == "/api/Users" and request.method.upper() == "POST":
            return self._register(request)
        if path == "/rest/user/login" and request.method.upper() == "POST":
            return self._login(request)
        if path == "/rest/user/whoami":
            return self._whoami(request)
        if path == "/api/Users":
            if not self._user_for(request):
                return self._send(401, {"error": "denied"})
            return self._send(200, {"data": [{"id": user["id"], "email": user["email"]} for user in self.users]})
        if path == "/api/Users/1":
            if not self._user_for(request):
                return self._send(401, {"error": "denied"})
            return self._send(200, {"id": 1, "email": "admin@juice-sh.op"})
        if path.startswith("/rest/basket/"):
            if not self._user_for(request):
                return self._send(401, {"error": "denied"})
            basket_id = int(path.rsplit("/", 1)[-1])
            return self._send(200, {"id": basket_id, "UserId": 1 if basket_id == 1 else basket_id})
        host = (urlsplit(str(request.url)).hostname or "").lower()
        if path == "/admin/users.html" and host == "zero.webappsecurity.com":
            page = "<html><table><tr><th>Name</th><th>Password</th><th>SSN</th></tr>" \
                   "<tr><td>Example Person</td><td>example-secret</td><td>000-00-0000</td></tr></table></html>"
            return self._send(200, page, "text/html")
        if "tomcat-missing" in path:
            page = "<html><title>Apache Tomcat/9.0.0 - Error report</title></html>"
            return self._send(404, page, "text/html")
        return self._send(404, "missing", "text/plain")

    def _register(self, request):
        data = json.loads(request.content or b"{}")
        password = str(data.get("password", ""))
        self.secrets.append(password)
        user = {"id": self.next_id, "email": data.get("email"), "role": data.get("role") or "customer",
                "password": password, "basket": self.next_id}
        self.next_id += 1
        self.users.append(user)
        return self._send(201, {"data": {"id": user["id"], "email": user["email"], "role": user["role"]}})

    def _login(self, request):
        data = json.loads(request.content or b"{}")
        user = next((item for item in self.users if item["email"] == data.get("email") and item["password"] == data.get("password")), None)
        if not user:
            return self._send(401, {"error": "denied"})
        token = "labtoken-" + uuid4().hex
        user["token"] = token
        self.secrets.append(token)
        return self._send(200, {"authentication": {"token": token, "bid": user["basket"], "umail": user["email"]}})

    def _whoami(self, request):
        user = self._user_for(request)
        if not user:
            return self._send(401, {"error": "denied"})
        return self._send(200, {"user": {"id": user["id"], "email": user["email"], "role": user["role"]}})

    def _user_for(self, request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else ""
        return next((user for user in self.users if user.get("token") == token), None)

    def _send(self, status, body, content_type="application/json"):
        run_id = str(uuid4())
        raw = body if isinstance(body, str) else json.dumps(body)
        self.store.add_run(run_id, {"response": {"status": status, "body": raw}})
        return httpx.Response(status, content=raw.encode(), headers={"Content-Type": content_type, "X-Charter-Run": run_id})
