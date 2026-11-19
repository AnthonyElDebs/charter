import json
import os
import unittest

import httpx

from app.llm import Llm, LlmError, infer_api


class LlmTests(unittest.TestCase):
    def test_provider_inference(self):
        self.assertEqual(infer_api("https://api.anthropic.com"), "anthropic")
        self.assertEqual(infer_api("http://127.0.0.1:11434"), "ollama")
        self.assertEqual(infer_api("https://api.openai.com/v1"), "openai")

    def test_anthropic_request_shape(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            seen["key"] = request.headers.get("x-api-key")
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"content": [{"type": "text", "text": "pong"}],
                                             "usage": {"input_tokens": 2, "output_tokens": 1}})

        llm = Llm("https://api.anthropic.com", "anthropic", "test-key", "claude-sonnet-4-5",
                  client=httpx.Client(transport=httpx.MockTransport(handler)))
        text, tokens = llm.complete("system", "ping")
        self.assertEqual(text, "pong")
        self.assertEqual(tokens, 3)
        self.assertEqual(seen["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(seen["key"], "test-key")
        self.assertEqual(seen["body"]["temperature"], 0)
        self.assertNotIn("sk-", json.dumps(seen["body"]))

    def test_openai_and_ollama_shapes(self):
        def openai(request):
            self.assertEqual(request.headers.get("authorization"), "Bearer test-key")
            self.assertTrue(str(request.url).endswith("/v1/chat/completions"))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 4}})

        def ollama(request):
            self.assertEqual(str(request.url), "http://localhost:11434/api/chat")
            body = json.loads(request.content)
            self.assertFalse(body["stream"])
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, json={"message": {"content": "ok"}, "prompt_eval_count": 1, "eval_count": 1})

        openai_llm = Llm("https://example.test/v1", "openai", "test-key", "m",
                         client=httpx.Client(transport=httpx.MockTransport(openai)))
        self.assertEqual(openai_llm.complete("s", "u")[0], "ok")
        ollama_llm = Llm("http://localhost:11434", "ollama", "", "m",
                         client=httpx.Client(transport=httpx.MockTransport(ollama)))
        self.assertEqual(ollama_llm.complete("s", "u")[0], "ok")

    def test_from_env_requires_a_key_except_for_ollama(self):
        previous = {name: os.environ.get(name) for name in
                    ("CHARTER_LLM_BASE_URL", "CHARTER_LLM_API", "CHARTER_LLM_API_KEY", "CHARTER_LLM_MODEL")}
        try:
            os.environ["CHARTER_LLM_BASE_URL"] = "https://api.anthropic.com"
            os.environ["CHARTER_LLM_MODEL"] = "claude-sonnet-4-5"
            os.environ.pop("CHARTER_LLM_API", None)
            os.environ.pop("CHARTER_LLM_API_KEY", None)
            with self.assertRaises(LlmError):
                Llm.from_env()
            os.environ["CHARTER_LLM_BASE_URL"] = "http://127.0.0.1:11434"
            os.environ["CHARTER_LLM_MODEL"] = "llama"
            llm = Llm.from_env()
            self.assertEqual(llm.api, "ollama")
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_error_body_redacts_the_key(self):
        def handler(request):
            return httpx.Response(401, text="rejected test-key")

        llm = Llm("https://api.anthropic.com", "anthropic", "test-key", "m",
                  client=httpx.Client(transport=httpx.MockTransport(handler)))
        with self.assertRaises(LlmError) as caught:
            llm.complete("s", "u")
        self.assertNotIn("test-key", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
