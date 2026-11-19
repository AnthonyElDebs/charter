"""Call an Anthropic, OpenAI-compatible, or Ollama endpoint configured only by environment."""
import json
import os
from urllib.parse import urlsplit, urlunsplit

import httpx


class LlmError(RuntimeError):
    pass


def infer_api(base_url):
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if "anthropic.com" in host:
        return "anthropic"
    if "ollama" in host or parts.port == 11434:
        return "ollama"
    return "openai"


def _estimate(*parts):
    return sum(max(1, len(part) // 4) for part in parts)


class Llm:
    def __init__(self, base_url, api, api_key, model, *, max_tokens=2048, api_version="2023-06-01", client=None):
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise LlmError("CHARTER_LLM_BASE_URL must be an HTTP(S) URL")
        if api not in {"anthropic", "openai", "ollama"}:
            raise LlmError("CHARTER_LLM_API must be anthropic, openai, or ollama")
        if api != "ollama" and not api_key:
            raise LlmError("Set CHARTER_LLM_API_KEY for this endpoint")
        self.base_url = base_url.rstrip("/")
        self.api = api
        self.api_key = api_key or ""
        self.model = model
        self.max_tokens = max_tokens
        self.api_version = api_version
        self.client = client or httpx.Client(trust_env=False, timeout=httpx.Timeout(120.0, connect=20.0))

    @classmethod
    def from_env(cls):
        base = os.environ.get("CHARTER_LLM_BASE_URL", "").strip()
        model = os.environ.get("CHARTER_LLM_MODEL", "").strip()
        api = os.environ.get("CHARTER_LLM_API", "").strip().lower()
        key = os.environ.get("CHARTER_LLM_API_KEY", "").strip()
        if not base or not model:
            raise LlmError("Set CHARTER_LLM_BASE_URL and CHARTER_LLM_MODEL")
        if not api:
            api = infer_api(base)
        try:
            max_tokens = int(os.environ.get("CHARTER_LLM_MAX_TOKENS", "2048"))
        except ValueError as exc:
            raise LlmError("CHARTER_LLM_MAX_TOKENS must be an integer") from exc
        version = os.environ.get("CHARTER_LLM_API_VERSION", "2023-06-01").strip() or "2023-06-01"
        return cls(base, api, key, model, max_tokens=max_tokens, api_version=version)

    def endpoint(self, suffix):
        if self.api == "ollama":
            parts = urlsplit(self.base_url)
            return urlunsplit((parts.scheme, parts.netloc, "/api/chat", "", ""))
        if self.base_url.endswith("/v1") and suffix.startswith("v1/"):
            suffix = suffix[3:]
        return self.base_url + "/" + suffix

    def complete(self, system, user):
        if self.api == "anthropic":
            url = self.endpoint("v1/messages")
            headers = {"x-api-key": self.api_key, "anthropic-version": self.api_version,
                       "content-type": "application/json"}
            body = {"model": self.model, "max_tokens": self.max_tokens, "temperature": 0,
                    "system": system, "messages": [{"role": "user", "content": user}]}
            parse = _anthropic_text
            usage = _anthropic_usage
        elif self.api == "ollama":
            url = self.endpoint("api/chat")
            headers = {"content-type": "application/json"}
            if self.api_key:
                headers["authorization"] = "Bearer " + self.api_key
            body = {"model": self.model, "stream": False, "options": {"temperature": 0},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
            parse = _ollama_text
            usage = _ollama_usage
        else:
            url = self.endpoint("v1/chat/completions")
            headers = {"content-type": "application/json", "authorization": "Bearer " + self.api_key}
            body = {"model": self.model, "temperature": 0, "max_tokens": self.max_tokens,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
            parse = _openai_text
            usage = _openai_usage
        try:
            response = self.client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise LlmError(f"model endpoint unreachable ({type(exc).__name__})") from exc
        text = response.text
        if self.api_key:
            text = text.replace(self.api_key, "[redacted]")
        if response.status_code >= 400:
            raise LlmError(f"model endpoint returned {response.status_code}: {text[:300]}")
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise LlmError("model endpoint returned non-JSON") from exc
        try:
            answer = parse(payload)
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError("model response did not include text") from exc
        return answer, usage(payload, system, user, answer)


def _anthropic_text(payload):
    parts = [block.get("text", "") for block in payload.get("content") or []
             if isinstance(block, dict) and block.get("type") == "text"]
    if not parts:
        raise KeyError("content")
    return "".join(parts)


def _openai_text(payload):
    content = payload["choices"][0]["message"]["content"]
    if isinstance(content, list):
        return "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)
    return str(content)


def _ollama_text(payload):
    content = payload["message"]["content"]
    return str(content)


def _counted(payload, system, user, answer, count):
    return count if count else _estimate(system, user, answer)


def _anthropic_usage(payload, system, user, answer):
    usage = payload.get("usage") or {}
    return _counted(payload, system, user, answer,
                    int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0))


def _openai_usage(payload, system, user, answer):
    return _counted(payload, system, user, answer, int((payload.get("usage") or {}).get("total_tokens") or 0))


def _ollama_usage(payload, system, user, answer):
    return _counted(payload, system, user, answer,
                    int(payload.get("prompt_eval_count") or 0) + int(payload.get("eval_count") or 0))
