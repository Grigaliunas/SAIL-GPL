"""Strict JSON encoding and SHA-256 helpers for the SAI (Super AI) SRM format.

The local canonical encoding is UTF-8 JSON without a BOM or whitespace, with
object keys sorted by Unicode code point. Unicode is not normalized. JSON
strings use Python's standard JSON escaping with ``ensure_ascii=False``.
Only objects with string keys, arrays, strings, integers, booleans and null
are supported. Floats, duplicate keys and unpaired surrogates are rejected.
This is a versioned local encoding, with no RFC 8785 interoperability claim.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

HASH_ALG = "sha256"
_CHUNK = 1024 * 1024


def _validate(value: Any, active: set[int]) -> None:
    kind = type(value)
    if kind in (str, int, bool) or value is None:
        if kind is str:
            value.encode("utf-8", errors="strict")
        return
    if kind not in (dict, list):
        raise ValueError(f"unsupported JSON value type: {kind.__name__}")
    identity = id(value)
    if identity in active:
        raise ValueError("cyclic JSON value")
    active.add(identity)
    try:
        if kind is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("JSON object keys must be strings")
                key.encode("utf-8", errors="strict")
                _validate(item, active)
        else:
            for item in value:
                _validate(item, active)
    finally:
        active.remove(identity)


def cjson(obj: Any) -> bytes:
    """Encode a supported JSON value using the local canonical format."""
    try:
        _validate(obj, set())
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except RecursionError as exc:
        raise ValueError("JSON value is nested too deeply") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _unsupported_number(value: str):
    raise ValueError(f"floating-point and non-finite JSON numbers are unsupported: {value}")


def load_json(data: str | bytes) -> Any:
    """Parse strict UTF-8 JSON, rejecting duplicate keys and unsupported values."""
    if type(data) is bytes:
        data = data.decode("utf-8", errors="strict")
    elif type(data) is not str:
        raise ValueError("JSON input must be UTF-8 bytes or text")
    try:
        value = json.loads(
            data, object_pairs_hook=_unique_object,
            parse_float=_unsupported_number, parse_constant=_unsupported_number,
        )
        _validate(value, set())
        return value
    except RecursionError as exc:
        raise ValueError("JSON value is nested too deeply") from exc


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
    """Decode canonical padded base64 without whitespace or ignored characters."""
    if type(text) is not str:
        raise ValueError("base64 value must be a string")
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error) as exc:
        raise ValueError("invalid base64 value") from exc
    if b64e(decoded) != text:
        raise ValueError("noncanonical base64 value")
    return decoded
