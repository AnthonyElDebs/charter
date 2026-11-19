import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import httpx

import lab
from app.governor import Governor
from app.llm import Llm
from app.loop import run_campaign
from app.worker_config import TARGET
from tests.fakes import MemoryStore, Shop


def quiet():
    return Governor(6, 80, 100000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _seconds: None)


class Script:
    def __init__(self, plan):
        self.plan = plan
        self.messages = []

    def complete(self, system, user):
        self.messages.append((system, user))
        return self.plan(system, user)


def chain_plan(_system, user):
    payload = json.loads(user)
    if any(item.get("proven") for item in payload["findings"]):
        return json.dumps({"summary": "goal met", "goal_proven": True, "done": True, "tasks": []}), 10
    if "Authenticated." in user:
        return json.dumps({"summary": "compare objects", "tasks": [
            {"worker": "api-top10", "intent": "read another account", "check": "bola"}]}), 10
    if payload["observations"]:
        return json.dumps({"summary": "sign in", "tasks": [
            {"worker": "api-top10", "intent": "create a lab session", "check": "auth-setup"}]}), 10
    return json.dumps({"summary": "map", "tasks": [{"worker": "recon", "intent": "map the origin"}]}), 10


class LoopTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "approved"
        lab.approve(Path(temp.name), "test-fixture")
        self.store = MemoryStore()
        self.shop = Shop(self.store)

    def campaign(self, plan, **kwargs):
        script = Script(plan)
        options = {"lab": True, "governor": quiet(), "approval": None}
        options.update(kwargs)
        result = run_campaign(
            "Prove broken access control.", root=self.root, store=self.store, llm=script,
            charter={"allow": [TARGET], "deny": [TARGET + "private"]},
            transport=self.shop.transport(), target=TARGET, **options)
        return result, script

    def test_lab_chain_proves_access_control_without_leaking_secrets(self):
        class Boom:
            def require(self, *_args):
                raise AssertionError("lab mode must not ask for approval")

        result, script = self.campaign(chain_plan, approval=Boom())
        self.assertEqual(result.state, "proven")
        urls = self.shop.urls
        login_at = urls.index(next(url for url in urls if "/rest/user/login" in url))
        self.assertLess(urls.index(next(url for url in urls if url.endswith("/rest/products"))), login_at)
        self.assertTrue(any(url.rstrip("/").endswith("/api/Users") for url in urls[login_at + 1:]))
        self.assertTrue(any("/rest/basket/" in url for url in urls[login_at + 1:]))
        self.assertTrue(all("juice-shop" in url and "evil.example" not in url for url in urls))
        blob = "\n".join(user for _system, user in script.messages)
        self.assertNotIn("example-secret", blob)
        for secret in self.shop.secrets:
            self.assertNotIn(secret, blob)
        self.assertIn("admin@juice-sh.op", blob)
        self.assertIn("<untrusted_tool_output>", script.messages[-1][1])
        self.assertNotIn("<untrusted_tool_output>", script.messages[-1][0])
        self.assertIn("Ignore", script.messages[0][0])

    def test_goal_claim_without_a_finding_is_not_proven(self):
        def claim(_system, _user):
            return json.dumps({"summary": "done", "goal_proven": True, "tasks": []}), 5

        result, script = self.campaign(claim, governor=Governor(3, 80, 1000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _s: None))
        self.assertNotEqual(result.state, "proven")
        self.assertFalse(any(item.get("proven") for item in result.findings))
        self.assertGreaterEqual(len(script.messages), 1)
        self.assertTrue(all("evil.example" not in url for url in self.shop.urls))

    def test_request_budget_stops_after_one_send(self):
        def recon(_system, _user):
            return json.dumps({"summary": "map", "tasks": [{"worker": "recon", "intent": "map"}]}), 5

        result, _script = self.campaign(recon, governor=Governor(3, 1, 1000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _s: None))
        self.assertEqual(result.state, "exhausted")
        self.assertEqual(len(self.shop.urls), 1)

    def test_out_of_scope_plan_sends_nothing(self):
        def hostile(_system, _user):
            return json.dumps({"summary": "no", "tasks": [
                {"worker": "http", "intent": "bad", "method": "TRACE", "url": TARGET},
                {"worker": "http", "intent": "evil", "method": "GET", "url": "http://evil.example/"},
                {"worker": "http", "intent": "denied", "method": "GET", "url": TARGET + "private"},
            ]}), 5

        result, _script = self.campaign(hostile, governor=Governor(3, 80, 1000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _s: None))
        self.assertNotEqual(result.state, "proven")
        self.assertFalse(any("evil.example" in url for url in self.shop.urls))
        self.assertFalse(any(url.rstrip("/").endswith("/private") for url in self.shop.urls))
        self.assertTrue(self.store.blocks)

    def test_denied_approval_sends_nothing(self):
        class Deny:
            def __init__(self):
                self.called = False

            def require(self, *_args):
                self.called = True
                return "denied"

        deny = Deny()

        def recon(_system, _user):
            return json.dumps({"summary": "map", "tasks": [{"worker": "recon", "intent": "map"}]}), 5

        result, _script = self.campaign(recon, lab=False, approval=deny,
                                       governor=Governor(2, 10, 1000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _s: None))
        self.assertTrue(deny.called)
        self.assertEqual(self.shop.urls, [])
        self.assertEqual(result.state, "exhausted")

    def test_real_client_marks_a_done_plan_complete(self):
        seen = {}

        def handler(request):
            seen["key"] = request.headers.get("x-api-key")
            return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(
                {"summary": "nothing else", "done": True, "tasks": []})}], "usage": {"input_tokens": 1, "output_tokens": 1}})

        llm = Llm("https://api.anthropic.com", "anthropic", "test-key", "claude-sonnet-4-5",
                  client=httpx.Client(transport=httpx.MockTransport(handler)))
        result = run_campaign("Look.", root=self.root, store=self.store, llm=llm, lab=True, governor=quiet(),
                              charter={"allow": [TARGET], "deny": [TARGET + "private"]},
                              transport=self.shop.transport(), target=TARGET)
        self.assertEqual(result.state, "complete")
        self.assertEqual(seen["key"], "test-key")


if __name__ == "__main__":
    unittest.main()
