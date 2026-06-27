"""Canonical serialization and hashing helpers.

A signature is only meaningful if signer and verifier agree, byte-for-byte, on
what was signed. We therefore serialize every signed payload (manifest,
attestation body) through one canonical form: UTF-8 JSON, keys sorted, no
insignificant whitespace. Verification re-derives the same bytes and compares.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

# §7.7 requires verification to be open and re-implementable, so the hash and
# encoding choices are deliberately boring: SHA-256 + RFC 8785-style canonical JSON.
HASH_ALG = "sha256"
_CHUNK = 1024 * 1024


def cjson(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
