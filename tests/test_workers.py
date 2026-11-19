from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import lab
from app.exchange import Client
from app.governor import Governor
from app.workers import execute, page_links, run_ffuf, run_injection, run_mass_assignment, run_nuclei, run_recon, run_sqlmap, run_zap
from tests.fakes import MemoryStore, Shop
from app.worker_config import TARGET


def quiet_governor():
    return Governor(4, 40, 1000, 0, monotonic_fn=lambda: 0, sleep_fn=lambda _seconds: None)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        lab.approve(self.folder, "test-fixture")
        self.store = MemoryStore()
        self.shop = Shop(self.store)
        self.client = Client(root=self.folder / "approved", charter={"allow": [TARGET], "deny": [TARGET + "private"]},
                             store=self.store, governor=quiet_governor(), transport=self.shop.transport(),
                             campaign_id="campaign", target=TARGET)

    def test_injection_and_mass_assignment(self):
        injected = run_injection({"intent": "compare search"}, self.client)
        self.assertTrue(any(item["check"] == "injection" and item["proven"] for item in injected.findings))
        assigned = run_mass_assignment({"intent": "extra role"}, self.client)
        self.assertTrue(any(item["check"] == "mass-assignment" and item["proven"] for item in assigned.findings))
        self.assertTrue(all("labtoken-" not in text for text in (injected.observation, assigned.observation)))

    def test_recon_follows_the_chosen_origin_and_withholds_secrets(self):
        lab.approve(self.folder, "test-fixture", target="http://zero.webappsecurity.com/")
        store = MemoryStore()
        shop = Shop(store)
        client = Client(root=self.folder / "approved", charter={"allow": ["http://zero.webappsecurity.com/"]},
                        store=store, governor=quiet_governor(), transport=shop.transport(),
                        campaign_id="campaign", target="http://zero.webappsecurity.com/")
        result = run_recon({"intent": "map the public demo"}, client)
        self.assertTrue(any(item["check"] == "sensitive-data" and item["proven"] for item in result.findings))
        self.assertNotIn("000-00-0000", result.observation)
        self.assertNotIn("example-secret", result.observation)
        self.assertTrue(all("evil.example" not in url for url in shop.urls))
        links = page_links("http://zero.webappsecurity.com/", "<a href=\"http://evil.example/steal\">x</a><a href=\"/faq.html\">f</a>")
        self.assertEqual(links, ["http://zero.webappsecurity.com/faq.html"])

    def test_ffuf_fallback_skips_a_denied_word(self):
        with patch("app.workers.shutil.which", return_value=None):
            result = run_ffuf({"intent": "paths", "url": TARGET + "FUZZ", "wordlist": ["rest", "private"]}, self.client)
        self.assertIn("not installed", result.observation)
        self.assertTrue(any(url.endswith("/rest") for url in self.shop.urls))
        self.assertFalse(any(url.endswith("/private") for url in self.shop.urls))

    def test_sqlmap_argv_is_fixed_and_the_child_env_drops_keys(self):
        captured = {}
        real_run = subprocess.run

        def fake_run(argv, **kwargs):
            if argv and str(argv[0]).endswith("sqlmap"):
                captured["argv"] = list(argv)
                captured["env"] = kwargs.get("env", {})
                return subprocess.CompletedProcess(argv, 0, b"ok", b"")
            return real_run(argv, **kwargs)

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "secret-value"}, clear=False), \
             patch("app.workers.shutil.which", return_value="/usr/bin/sqlmap"), \
             patch("app.workers.subprocess.run", fake_run):
            run_sqlmap({"intent": "check", "url": TARGET + "rest/products/search?q=1", "args": ["--os-shell"]}, self.client)
        self.assertIn("--batch", captured["argv"])
        self.assertIn("--proxy", captured["argv"])
        self.assertNotIn("--os-shell", captured["argv"])
        self.assertNotIn("ANTHROPIC_API_KEY", captured["env"])
        self.assertTrue(any(str(item).startswith("X-Charter-Campaign:") for item in captured["argv"]))

    def test_missing_scanners_send_nothing(self):
        with patch("app.workers.shutil.which", return_value=None):
            self.assertIn("not installed", run_nuclei({"intent": "scan", "url": TARGET}, self.client).observation)
            self.assertIn("not installed", run_zap({"intent": "scan", "url": TARGET}, self.client).observation)
        before = len(self.shop.urls)
        with patch("app.workers.shutil.which") as which:
            result = execute({"worker": "nuclei", "intent": "scan", "url": "http://evil.example/"}, self.client)
            which.assert_not_called()
        self.assertIn("refused", result.observation)
        self.assertEqual(len(self.shop.urls), before)


if __name__ == "__main__":
    unittest.main()
