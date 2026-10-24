"""Strict signing backends for SAI (Super AI) SRM wire format v2.

Ed25519 and ECDSA-P256 use DER SubjectPublicKeyInfo public keys. ML-DSA-65
uses the raw FIPS 204 public key through the optional liboqs runtime. Hybrid
signatures contain exactly one Ed25519 and one ML-DSA-65 component, in that
order, and both must verify. Key IDs are full SHA-256 public-key digests.
"""

from __future__ import annotations

import hashlib
import ctypes
import ctypes.util
import importlib.util
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .canonical import b64d, b64e, cjson, load_json

CLASSICAL = ("ed25519", "ecdsa-p256")
PQ = ("ml-dsa-65",)
HYBRID = "hybrid"
PQ_OQS_NAME = "ML-DSA-65"
DEFAULT_ALG = "ed25519"
_ALGORITHMS = CLASSICAL + PQ + (HYBRID,)
# Fixed FIPS 204 ML-DSA-65 sizes, also published by Open Quantum Safe.
_PQ_PUBLIC_BYTES, _PQ_SECRET_BYTES, _PQ_SIGNATURE_BYTES = 1952, 4032, 3309


def _algorithm(alg: str) -> str:
    if type(alg) is not str or alg not in _ALGORITHMS:
        raise ValueError(f"unknown algorithm: {alg!r}")
    return alg


def is_pq(alg: str) -> bool:
    """Identify only the supported PQ algorithms, never prefix aliases."""
    return type(alg) is str and alg in PQ + (HYBRID,)


def key_id(public_material: bytes) -> str:
    return hashlib.sha256(public_material).hexdigest()


def _native_oqs_available() -> bool:
    """Find an existing native runtime without invoking oqs's auto-installer."""
    prefix = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    candidates = [ctypes.util.find_library("oqs"), ctypes.util.find_library("liboqs")]
    for directory in ("lib", "lib64", "bin"):
        for filename in ("liboqs.dylib", "liboqs.so", "oqs.dll", "liboqs.dll"):
            path = prefix / directory / filename
            if path.is_file():
                candidates.append(str(path))
    for candidate in candidates:
        if candidate:
            try:
                ctypes.CDLL(candidate)
                return True
            except OSError:
                pass
    return False


def _require_oqs():
    if importlib.util.find_spec("oqs") is None or not _native_oqs_available():
        raise RuntimeError(
            "post-quantum signing needs liboqs-python and an installed compatible "
            "liboqs runtime. Set OQS_INSTALL_PATH to its prefix when needed; "
            "SAI does not download or build native libraries during verification."
        )
    try:
        import oqs  # type: ignore
    except (Exception, SystemExit) as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "post-quantum signing needs liboqs-python and a compatible liboqs "
            "runtime. Install the optional dependency: pip install 'sail-toolkit[pq]'."
        ) from exc
    if PQ_OQS_NAME not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError("the installed liboqs runtime does not enable ML-DSA-65")
    return oqs


def _shape(value: dict, required: set[str], optional: set[str] | None = None) -> None:
    if type(value) is not dict or not required <= value.keys():
        raise ValueError("signature or key object is missing required fields")
    if not value.keys() <= required | (optional or set()):
        raise ValueError("signature or key object contains unsupported fields")


def _classical_private(alg: str, keyfile: bytes):
    private = serialization.load_pem_private_key(keyfile, password=None)
    if alg == "ed25519" and not isinstance(private, ed25519.Ed25519PrivateKey):
        raise ValueError("ed25519 requires an Ed25519 private key")
    if alg == "ecdsa-p256" and not (
        isinstance(private, ec.EllipticCurvePrivateKey)
        and isinstance(private.curve, ec.SECP256R1)
    ):
        raise ValueError("ecdsa-p256 requires a P-256 private key")
    return private


def _classical_public(alg: str, material: bytes):
    public = serialization.load_der_public_key(material)
    if alg == "ed25519" and not isinstance(public, ed25519.Ed25519PublicKey):
        raise ValueError("ed25519 requires an Ed25519 public key")
    if alg == "ecdsa-p256" and not (
        isinstance(public, ec.EllipticCurvePublicKey)
        and isinstance(public.curve, ec.SECP256R1)
    ):
        raise ValueError("ecdsa-p256 requires a P-256 public key")
    if public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != material:
        raise ValueError("public key must use canonical DER SubjectPublicKeyInfo")
    return public


def _public_material(alg: str, material: bytes) -> dict:
    _algorithm(alg)
    if alg in CLASSICAL:
        _classical_public(alg, material)
    elif alg == "ml-dsa-65":
        if len(material) != _PQ_PUBLIC_BYTES:
            raise ValueError("invalid ML-DSA-65 public key length")
    else:
        raise ValueError("a hybrid public key requires two component descriptors")
    return {"alg": alg, "public_key": b64e(material), "key_id": key_id(material)}


def _hybrid_descriptor(parts: list[dict]) -> dict:
    return {
        "alg": HYBRID,
        "signatures": parts,
        "key_id": key_id(b"".join(b64d(part["public_key"]) for part in parts)),
    }


def descriptor(sig: dict) -> dict:
    """Validate a signature or public descriptor and return its public fields.

    Invalid or unknown shapes raise ValueError. Hybrid descriptors have exactly
    two ``signatures`` descriptors, ordered Ed25519 then ML-DSA-65.
    """
    if type(sig) is not dict:
        raise ValueError("signature must be an object")
    alg = _algorithm(sig.get("alg"))
    if alg == HYBRID:
        _shape(sig, {"alg", "key_id", "signatures"})
        parts = sig["signatures"]
        if type(parts) is not list or len(parts) != 2:
            raise ValueError("hybrid requires exactly two signatures")
        for part, expected in zip(parts, ("ed25519", "ml-dsa-65")):
            if type(part) is not dict or part.get("alg") != expected:
                raise ValueError("hybrid requires Ed25519 then ML-DSA-65")
        result = _hybrid_descriptor([descriptor(part) for part in parts])
    else:
        _shape(sig, {"alg", "public_key", "key_id"}, {"signature"})
        result = _public_material(alg, b64d(sig["public_key"]))
        if "signature" in sig:
            signature = b64d(sig["signature"])
            if not signature:
                raise ValueError("signature must not be empty")
            if alg == "ed25519" and len(signature) != 64:
                raise ValueError("invalid Ed25519 signature length")
            if alg == "ml-dsa-65" and len(signature) != _PQ_SIGNATURE_BYTES:
                raise ValueError("invalid ML-DSA-65 signature length")
    if type(sig["key_id"]) is not str or sig["key_id"] != result["key_id"]:
        raise ValueError("key_id does not match the public key material")
    return result


@dataclass(frozen=True)
class PublicKey:
    alg: str
    material: bytes

    @property
    def key_id(self) -> str:
        return key_id(self.material)

    def to_envelope(self) -> dict:
        return _public_material(self.alg, self.material)

    @staticmethod
    def from_envelope(value: dict) -> "PublicKey":
        public = descriptor(value)
        if public["alg"] == HYBRID:
            raise ValueError("PublicKey represents a single algorithm")
        return PublicKey(public["alg"], b64d(public["public_key"]))


def _pq_keyfile(keyfile: bytes) -> dict:
    value = load_json(keyfile)
    _shape(value, {"alg", "secret_key", "public_key"})
    if value["alg"] != "ml-dsa-65":
        raise ValueError("expected an ML-DSA-65 keyfile")
    if len(b64d(value["secret_key"])) != _PQ_SECRET_BYTES:
        raise ValueError("invalid ML-DSA-65 secret key length")
    _public_material("ml-dsa-65", b64d(value["public_key"]))
    return value


def _hybrid_keyfile(keyfile: bytes) -> dict:
    value = load_json(keyfile)
    _shape(value, {"alg", "ed25519", "ml_dsa"})
    if value["alg"] != HYBRID or type(value["ed25519"]) is not str:
        raise ValueError("expected a hybrid keyfile with an Ed25519 PEM key")
    if type(value["ml_dsa"]) is not dict:
        raise ValueError("expected an ML-DSA-65 key object")
    return value


def generate_keyfile(alg: str) -> bytes:
    """Return an unencrypted private keyfile; persist with write_private_key."""
    _algorithm(alg)
    if alg in CLASSICAL:
        private = (
            ed25519.Ed25519PrivateKey.generate() if alg == "ed25519"
            else ec.generate_private_key(ec.SECP256R1())
        )
        return private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    if alg == "ml-dsa-65":
        oqs = _require_oqs()
        with oqs.Signature(PQ_OQS_NAME) as signer:
            public = signer.generate_keypair()
            secret = signer.export_secret_key()
        value = cjson({"alg": alg, "secret_key": b64e(secret), "public_key": b64e(public)})
        _pq_keyfile(value)
        return value
    return cjson({
        "alg": HYBRID, "ed25519": generate_keyfile("ed25519").decode("ascii"),
        "ml_dsa": load_json(generate_keyfile("ml-dsa-65")),
    })


def public_descriptor(alg: str, keyfile: bytes) -> dict:
    """Derive the validated public descriptor of a private keyfile."""
    _algorithm(alg)
    if alg in CLASSICAL:
        public = _classical_private(alg, keyfile).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return _public_material(alg, public)
    if alg == "ml-dsa-65":
        value = _pq_keyfile(keyfile)
        return _public_material(alg, b64d(value["public_key"]))
    value = _hybrid_keyfile(keyfile)
    return _hybrid_descriptor([
        public_descriptor("ed25519", value["ed25519"].encode("ascii")),
        public_descriptor("ml-dsa-65", cjson(value["ml_dsa"])),
    ])


def sign(alg: str, keyfile: bytes, data: bytes) -> dict:
    """Sign bytes with the exact declared algorithm and validated key type."""
    public = public_descriptor(alg, keyfile)
    if alg in CLASSICAL:
        private = _classical_private(alg, keyfile)
        signature = (
            private.sign(data) if alg == "ed25519"
            else private.sign(data, ec.ECDSA(hashes.SHA256()))
        )
        return {**public, "signature": b64e(signature)}
    if alg == "ml-dsa-65":
        oqs = _require_oqs()
        value = _pq_keyfile(keyfile)
        with oqs.Signature(PQ_OQS_NAME, b64d(value["secret_key"])) as signer:
            signature = signer.sign(data)
            if not signer.verify(data, signature, b64d(value["public_key"])):
                raise ValueError("ML-DSA-65 public and secret keys do not match")
        result = {**public, "signature": b64e(signature)}
        descriptor(result)
        return result
    value = _hybrid_keyfile(keyfile)
    return {
        **public,
        "signatures": [
            sign("ed25519", value["ed25519"].encode("ascii"), data),
            sign("ml-dsa-65", cjson(value["ml_dsa"]), data),
        ],
    }


def verify(sig_part: dict, data: bytes) -> bool:
    """Verify a strict signature object. Malformed input always fails closed."""
    try:
        public = descriptor(sig_part)
        alg = public["alg"]
        if alg == HYBRID:
            return all(verify(part, data) for part in sig_part["signatures"])
        signature = b64d(sig_part["signature"])
        material = b64d(public["public_key"])
        if alg == "ed25519":
            _classical_public(alg, material).verify(signature, data)
            return True
        if alg == "ecdsa-p256":
            _classical_public(alg, material).verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        oqs = _require_oqs()
        with oqs.Signature(PQ_OQS_NAME) as verifier:
            return bool(verifier.verify(data, signature, material))
    except Exception:
        return False


def write_private_key(path: Path, data: bytes) -> None:
    """Exclusively create a mode-0600 keyfile, refusing symlinks and clobbering.

    The destination's parent must already exist. If a write or permission
    check fails, remove only the file created by this call, never a replacement.
    """
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    created = os.fstat(fd)
    try:
        os.fchmod(fd, 0o600)
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise OSError("the destination filesystem cannot enforce private key permissions")
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                path.unlink()
        except OSError:
            pass
        raise
