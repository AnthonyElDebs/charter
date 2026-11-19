from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import lab


class LabEnvTests(unittest.TestCase):
    def test_template_settings_stay_and_the_password_is_kept(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        env = folder / "compose.env"
        env.write_text("CHARTER_LLM_BASE_URL=\nCHARTER_LLM_API=\nCHARTER_LLM_API_KEY=\nCHARTER_LLM_MODEL=\n",
                       encoding="utf-8")
        lab.approve(folder, "test-fixture")
        text = env.read_text(encoding="utf-8")
        self.assertIn("CHARTER_LLM_API_KEY=\n", text)
        self.assertIn("CHARTER_LLM_MODEL=\n", text)
        saved = next(line for line in text.splitlines() if line.startswith("CHARTER_DB_PASSWORD="))
        self.assertGreater(len(saved.split("=", 1)[1]), 20)
        lab.approve(folder, "test-fixture")
        renewed = env.read_text(encoding="utf-8")
        self.assertIn(saved, renewed.splitlines())
        self.assertEqual(renewed.count("CHARTER_DB_PASSWORD="), 1)


if __name__ == "__main__":
    unittest.main()
