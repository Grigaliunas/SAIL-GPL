"""Signing back-ends for SRM (SAIL-GPL §7.1, §7.5).

Algorithms are crypto-agile by design (§7.5): the chosen algorithm is always
declared in the signature envelope, so verifiers never have to guess and the
set can grow without breaking old artifacts.

Supported:
    ed25519       classical EdDSA              (default; via `cryptography`)
    ecdsa-p256    classical ECDSA / SHA-256    (via `cryptography`)
    ml-dsa-65     post-quantum, FIPS 204       (via `liboqs-python`, extra `pq`)
    hybrid        ed25519 + ml-dsa-65          (PQ + classical, T3 §8)

Keys are PEM (PKCS#8) for classical algorithms and a small JSON keyfile for
PQ / hybrid (liboqs exposes raw key bytes). `key_id` is a short SHA-256 of the
public key material and is stable across re-signs with the same key.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .canonical import b64d, b64e

CLASSICAL = ("ed25519", "ecdsa-p256")
PQ = ("ml-dsa-65",)
HYBRID = "hybrid"
PQ_OQS_NAME = "ML-DSA-65"
DEFAULT_ALG = "ed25519"


def is_pq(alg: str) -> bool:
    """True if `alg` provides post-quantum protection (PQ or hybrid)."""
    return alg in PQ or alg.startswith(HYBRID)


def key_id(public_material: bytes) -> str:
    return hashlib.sha256(public_material).hexdigest()[:16]


def _require_oqs():
    try:
        import oqs  # type: ignore
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "post-quantum signing needs liboqs-python. Install the optional "
            "dependency:  pip install 'sail-toolkit[pq]'  (or pip install liboqs-python)."
        ) from exc
    return oqs


# --------------------------------------------------------------------------- #
# Public material: what verifiers need, embedded in the signature envelope.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PublicKey:
    alg: str
    material: bytes  # DER SubjectPublicKeyInfo (classical) or raw bytes (PQ)

    @property
    def key_id(self) -> str:
        return key_id(self.material)

    def to_envelope(self) -> dict:
        return {"alg": self.alg, "public_key": b64e(self.material), "key_id": self.key_id}

    @staticmethod
    def from_envelope(d: dict) -> "PublicKey":
        return PublicKey(alg=d["alg"], material=b64d(d["public_key"]))


# --------------------------------------------------------------------------- #
# Key generation / loading
# --------------------------------------------------------------------------- #


def generate_keyfile(alg: str) -> bytes:
    """Return the bytes of a private keyfile for `alg` (to write to disk)."""
    if alg == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if alg == "ecdsa-p256":
        priv = ec.generate_private_key(ec.SECP256R1())
        return priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if alg == "ml-dsa-65":
        oqs = _require_oqs()
        with oqs.Signature(PQ_OQS_NAME) as signer:
            pub = signer.generate_keypair()
            sec = signer.export_secret_key()
        return json.dumps({"alg": alg, "secret_key": b64e(sec), "public_key": b64e(pub)}).encode()
    if alg.startswith(HYBRID):
        cls = generate_keyfile("ed25519")
        pq = generate_keyfile("ml-dsa-65")
        return json.dumps(
            {"alg": HYBRID, "ed25519": cls.decode(), "ml_dsa": json.loads(pq)}
        ).encode()
    raise ValueError(f"unknown algorithm: {alg}")


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #


def sign(alg: str, keyfile: bytes, data: bytes) -> dict:
    """Sign `data`, returning the signature portion of the envelope."""
    if alg == "ed25519":
        priv = serialization.load_pem_private_key(keyfile, password=None)
        sig = priv.sign(data)
        pub = priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return _single(alg, pub, sig)
    if alg == "ecdsa-p256":
        priv = serialization.load_pem_private_key(keyfile, password=None)
        sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
        pub = priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return _single(alg, pub, sig)
    if alg == "ml-dsa-65":
        oqs = _require_oqs()
        kf = json.loads(keyfile)
        with oqs.Signature(PQ_OQS_NAME, b64d(kf["secret_key"])) as signer:
            sig = signer.sign(data)
        return _single(alg, b64d(kf["public_key"]), sig)
    if alg.startswith(HYBRID):
        kf = json.loads(keyfile)
        c = sign("ed25519", kf["ed25519"].encode(), data)
        q = sign("ml-dsa-65", json.dumps(kf["ml_dsa"]).encode(), data)
        return {
            "alg": HYBRID,
            "signatures": [c, q],
            "key_id": key_id(b64d(c["public_key"]) + b64d(q["public_key"])),
        }
    raise ValueError(f"unknown algorithm: {alg}")


def _single(alg: str, pub: bytes, sig: bytes) -> dict:
    return {
        "alg": alg,
        "public_key": b64e(pub),
        "signature": b64e(sig),
        "key_id": key_id(pub),
    }


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify(sig_part: dict, data: bytes) -> bool:
    """Verify a signature part (as produced by `sign`) over `data`."""
    alg = sig_part["alg"]
    try:
        if alg == "ed25519":
            pub = serialization.load_der_public_key(b64d(sig_part["public_key"]))
            pub.verify(b64d(sig_part["signature"]), data)
            return True
        if alg == "ecdsa-p256":
            pub = serialization.load_der_public_key(b64d(sig_part["public_key"]))
            pub.verify(b64d(sig_part["signature"]), data, ec.ECDSA(hashes.SHA256()))
            return True
        if alg == "ml-dsa-65":
            oqs = _require_oqs()
            with oqs.Signature(PQ_OQS_NAME) as v:
                return bool(
                    v.verify(data, b64d(sig_part["signature"]), b64d(sig_part["public_key"]))
                )
        if alg == HYBRID:
            return all(verify(p, data) for p in sig_part["signatures"])
    except Exception:
        return False
    return False
