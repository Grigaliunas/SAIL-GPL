"""Native SAIL receipt with RFC 6962 Merkle inclusion and a pinned checkpoint key.

This is an offline receipt format. It is not a Sigstore bundle or a log client.
The caller must obtain the log verification key through a trusted channel.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from . import crypto
from .canonical import cjson, sha256_bytes

RECEIPT_TYPE = "https://sail-gpl.org/srm/transparency/v2"
CHECKPOINT_TYPE = "https://sail-gpl.org/srm/checkpoint/v2"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def valid_timestamp(value) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except ValueError:
        return False


def leaf_hash(manifest_bytes: bytes) -> bytes:
    """A leaf is the raw SHA-256 digest of the signed manifest, domain separated."""
    return hashlib.sha256(b"\x00" + hashlib.sha256(manifest_bytes).digest()).digest()


def inclusion_root(leaf: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    if type(index) is not int or type(size) is not int or size < 1 or not 0 <= index < size:
        raise ValueError("invalid Merkle leaf index or tree size")
    if not isinstance(path, list) or len(path) > 64 or any(len(p) != 32 for p in path):
        raise ValueError("invalid Merkle audit path")
    fn, sn, result = index, size - 1, leaf
    for sibling in path:
        if sn == 0:
            raise ValueError("Merkle audit path is too long")
        if fn & 1 or fn == sn:
            result = hashlib.sha256(b"\x01" + sibling + result).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            result = hashlib.sha256(b"\x01" + result + sibling).digest()
        fn >>= 1
        sn >>= 1
    if sn:
        raise ValueError("Merkle audit path is incomplete")
    return result


def check(proof, manifest_bytes: bytes, trusted_log_key) -> list[str]:
    try:
        if not isinstance(proof, dict) or proof.get("_type") != RECEIPT_TYPE or proof.get("schema_version") != "2":
            return ["unsupported transparency receipt format"]
        if trusted_log_key is None:
            return ["transparency receipt requires an externally trusted log key"]
        expected_key = crypto.descriptor(trusted_log_key)
        checkpoint, signature = proof.get("checkpoint"), proof.get("signature")
        if not isinstance(checkpoint, dict) or checkpoint.get("_type") != CHECKPOINT_TYPE:
            return ["missing or unsupported log checkpoint"]
        if crypto.descriptor(signature) != expected_key:
            return ["checkpoint signer does not match the trusted log key"]
        if not crypto.verify(signature, cjson(checkpoint)):
            return ["invalid checkpoint signature"]
        if checkpoint.get("log_id") != expected_key["key_id"]:
            return ["checkpoint log_id does not match its verification key"]
        if not valid_timestamp(checkpoint.get("issued_at")):
            return ["checkpoint issued_at must be a UTC timestamp"]
        if proof.get("manifest_sha256") != sha256_bytes(manifest_bytes):
            return ["transparency receipt belongs to a different manifest"]
        root_hex, path = checkpoint.get("root_hash"), proof.get("audit_path")
        if not isinstance(root_hex, str) or not _HEX.fullmatch(root_hex):
            return ["invalid checkpoint root_hash"]
        if (not isinstance(path, list) or len(path) > 64
                or any(not isinstance(p, str) or not _HEX.fullmatch(p) for p in path)):
            return ["invalid Merkle audit_path"]
        root = inclusion_root(leaf_hash(manifest_bytes), proof.get("leaf_index"),
                              checkpoint.get("tree_size"), [bytes.fromhex(p) for p in path])
        if root.hex() != root_hex:
            return ["Merkle inclusion proof does not match the checkpoint"]
        return []
    except (ValueError, TypeError, KeyError, OverflowError):
        return ["malformed transparency receipt or trusted log key"]
