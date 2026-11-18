"""Exercise the public CLI with a temporary lab key and a real detached signature."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAB = "http://127.0.0.1:3000"


class ScopeCheck(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.run_tool("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "key")
        public_key = (self.folder / "key.pub").read_text().strip()
        (self.folder / "signers").write_text("lab-owner " + public_key + "\n", encoding="ascii")
        auth = self.folder / "authorization.txt"
        auth.write_bytes(b"Test fixture for offline classification only.")
        self.charter = json.loads((ROOT / "examples" / "juice-shop.json").read_bytes())
        now = datetime.now(timezone.utc)
        self.charter.update(
            authorization_sha256=sha256(auth.read_bytes()).hexdigest(),
            starts_at=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ends_at=(now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.sign()

    def run_tool(self, *argv, check=True):
        return subprocess.run(argv, cwd=self.folder, capture_output=True, text=True,
                              check=check, timeout=15)

    def sign(self):
        (self.folder / "charter.json").write_text(json.dumps(self.charter), encoding="utf-8")
        (self.folder / "charter.json.sig").unlink(missing_ok=True)
        self.run_tool("ssh-keygen", "-Y", "sign", "-f", "key", "-n", "charter-scope-v1", "charter.json")

    def classify(self, url, *, audit="audit.jsonl"):
        return self.run_tool(sys.executable, str(ROOT / "charter.py"), url,
                             "--charter", "charter.json", "--signature", "charter.json.sig",
                             "--signers", "signers", "--authorization", "authorization.txt",
                             "--audit", audit, check=False)

    def test_rules_and_private_audit(self):
        cases = {LAB: True, LAB + "/private-info": True, LAB + "/private": False,
                 LAB + "/private/notes": False, LAB + "/public/../private": False,
                 LAB + "/%70rivate": False, "http://127.0.0.1:3001/": False,
                 "https://127.0.0.1:3000/": False, "http://example.invalid/": False,
                 LAB + "/public?token=secret-example": True}
        for url, allowed in cases.items():
            with self.subTest(url=url):
                result = self.classify(url)
                self.assertEqual(result.returncode, 0 if allowed else 1, result.stderr + result.stdout)
        log = (self.folder / "audit.jsonl").read_text()
        self.assertNotIn("secret-example", log)
        events = [json.loads(line) for line in log.splitlines()]
        self.assertEqual([event["decision"] for event in events],
                         ["IN_SCOPE" if allowed else "DENY" for allowed in cases.values()])

    def test_modified_charter(self):
        with (self.folder / "charter.json").open("a") as file:
            file.write(" ")
        self.assertIn("signature", self.classify(LAB).stdout)

    def test_missing_charter(self):
        (self.folder / "charter.json").unlink()
        self.assertEqual(self.classify(LAB).returncode, 1)
        self.assertEqual(json.loads((self.folder / "audit.jsonl").read_text())["decision"], "DENY")

    def test_changed_authorization(self):
        (self.folder / "authorization.txt").write_bytes(b"different")
        self.assertIn("digest mismatch", self.classify(LAB).stdout)

    def test_untrusted_signer(self):
        (self.folder / "signers").write_text("")
        self.assertIn("signer trust", self.classify(LAB).stdout)

    def test_expired_window(self):
        self.charter["starts_at"] = "2000-01-01T00:00:00Z"
        self.charter["ends_at"] = "2000-01-02T00:00:00Z"
        self.sign()
        self.assertIn("time window", self.classify(LAB).stdout)

    def test_audit_unavailable(self):
        result = self.classify(LAB, audit=".")
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not write audit", result.stderr)


if __name__ == "__main__":
    unittest.main()
