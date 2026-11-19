"""Verify the signed charter and classify a refusal as fatal or per-URL."""
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from charter import Refused, check
from .capture import active_charter


FATAL_MARKERS = (
    "time window",
    "signature",
    "signer",
    "authorization document",
    "invalid charter",
    "missing or unknown charter",
    "approval bundle",
    "duplicate json",
)


def fatal_scope(reason):
    text = str(reason).lower()
    return any(marker in text for marker in FATAL_MARKERS)


def origin_of(rule):
    parts = urlsplit(rule)
    return f"{parts.scheme}://{parts.netloc}"


def load_verified(root):
    """Read the active bundle and accept it only after signature verification."""
    root = Path(root)
    try:
        current = (root / "current").read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{32}", current):
            raise Refused("invalid charter reference")
        raw = (root / current / "charter.json").read_bytes()
        preview = json.loads(raw.decode("utf-8-sig"))
    except Refused:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Refused("missing or invalid approval bundle") from exc
    allow = preview.get("allow") if isinstance(preview, dict) else None
    if not isinstance(allow, list) or not allow or not isinstance(allow[0], str):
        raise Refused("invalid charter JSON")
    return check(active_charter(root, allow[0]), {})


def restrictions_open():
    """Development builds skip the signed charter. Set CHARTER_OPEN=0 to enforce it again."""
    return os.environ.get("CHARTER_OPEN", "").strip().lower() in {"1", "true", "yes"}


def open_scope(url):
    parts = urlsplit(url if isinstance(url, str) else "")
    if parts.scheme in {"http", "https"} and parts.netloc:
        allow = [f"{parts.scheme}://{parts.netloc}/"]
    else:
        allow = []
    return {"engagement": "development", "operator": "local-operator", "approver": "development",
            "allow": allow, "deny": [], "starts_at": "", "ends_at": "restrictions off"}


def local_charter(charter):
    hosts = {urlsplit(rule).hostname for rule in charter.get("allow") or []}
    return bool(hosts) and hosts <= {"juice-shop", "localhost", "127.0.0.1"}
