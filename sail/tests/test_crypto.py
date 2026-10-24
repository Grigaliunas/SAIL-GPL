"""Cryptographic regressions, descriptor checks and optional real liboqs tests."""

import copy
import importlib.util
import os
import stat

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, rsa

from sail import crypto
from sail.canonical import b64d, b64e, cjson


@pytest.fixture
def ed_signature():
    return crypto.sign("ed25519", crypto.generate_keyfile("ed25519"), b"payload")


def _pem(private):
    return private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _hybrid_shape(ed_signature):
    """A descriptor fixture only; its PQ bytes are not cryptographic evidence."""
    material = b"q" * 1952
    pq = {"alg": "ml-dsa-65", "public_key": b64e(material),
          "key_id": crypto.key_id(material), "signature": b64e(b"s" * 3309)}
    return {"alg": "hybrid", "signatures": [ed_signature, pq],
            "key_id": crypto.key_id(b64d(ed_signature["public_key"]) + material)}


@pytest.mark.parametrize("alg", crypto.CLASSICAL)
def test_classical_roundtrip_and_descriptor(alg):
    key = crypto.generate_keyfile(alg)
    signature = crypto.sign(alg, key, b"payload")
    assert crypto.verify(signature, b"payload")
    assert not crypto.verify(signature, b"changed")
    assert crypto.descriptor(signature) == crypto.public_descriptor(alg, key)
    assert len(signature["key_id"]) == 64
    assert not crypto.verify(crypto.descriptor(signature), b"payload")
    assert crypto.PublicKey.from_envelope(signature).to_envelope() == crypto.descriptor(signature)


@pytest.mark.parametrize("value", [None, [], {}, {"alg": None}, {"alg": "unknown"},
    {"alg": "hybrid", "signatures": []}, {"alg": "hybrid-fake", "signatures": []}])
def test_malformed_signature_fails_closed(value):
    assert not crypto.verify(value, b"payload")
    with pytest.raises(ValueError):
        crypto.descriptor(value)


@pytest.mark.parametrize("alg", [None, "hybrid-fake", "ed448", "", 1, []])
def test_unknown_algorithms_are_not_pq_and_cannot_generate(alg):
    assert not crypto.is_pq(alg)
    with pytest.raises(ValueError):
        crypto.generate_keyfile(alg)


def test_exact_pq_algorithm_names():
    assert crypto.is_pq("ml-dsa-65")
    assert crypto.is_pq("hybrid")
    assert not crypto.is_pq("ed25519")


@pytest.mark.parametrize("field,value", [
    ("key_id", "0" * 64), ("key_id", 1), ("public_key", "bad"),
    ("public_key", None), ("signature", ""), ("signature", "Zg==\n"),
    ("signature", b64e(b"s" * 63)), ("extra", "unsupported"),
])
def test_invalid_signature_fields_rejected(ed_signature, field, value):
    ed_signature[field] = value
    assert not crypto.verify(ed_signature, b"payload")
    with pytest.raises(ValueError):
        crypto.descriptor(ed_signature)


@pytest.mark.parametrize("field", ["alg", "key_id", "public_key", "signature"])
def test_missing_signature_fields_rejected(ed_signature, field):
    del ed_signature[field]
    assert not crypto.verify(ed_signature, b"payload")


@pytest.mark.parametrize("alg,private", [
    ("ed25519", ed448.Ed448PrivateKey.generate()),
    ("ed25519", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ("ecdsa-p256", ec.generate_private_key(ec.SECP192R1())),
    ("ecdsa-p256", ec.generate_private_key(ec.SECP384R1())),
])
def test_signing_rejects_wrong_key_type_or_curve(alg, private):
    with pytest.raises(ValueError):
        crypto.public_descriptor(alg, _pem(private))
    with pytest.raises(ValueError):
        crypto.sign(alg, _pem(private), b"payload")


@pytest.mark.parametrize("curve", [ec.SECP192R1(), ec.SECP384R1()])
def test_verification_rejects_non_p256_ecdsa_even_with_valid_signature(curve):
    private = ec.generate_private_key(curve)
    public = _public(private)
    signature = {"alg": "ecdsa-p256", "public_key": b64e(public),
                 "key_id": crypto.key_id(public),
                 "signature": b64e(private.sign(b"payload", ec.ECDSA(hashes.SHA256())))}
    assert not crypto.verify(signature, b"payload")


def test_verification_rejects_ed448_labeled_ed25519():
    private = ed448.Ed448PrivateKey.generate()
    public = _public(private)
    signature = {"alg": "ed25519", "public_key": b64e(public),
                 "key_id": crypto.key_id(public), "signature": b64e(private.sign(b"payload"))}
    assert not crypto.verify(signature, b"payload")


def test_noncanonical_der_is_not_a_second_key_identity(ed_signature):
    material = b64d(ed_signature["public_key"]) + b"trailing data"
    ed_signature.update(public_key=b64e(material), key_id=crypto.key_id(material))
    assert not crypto.verify(ed_signature, b"payload")


def test_hybrid_descriptor_shape_and_id_without_pq_runtime(ed_signature):
    shape = _hybrid_shape(ed_signature)
    public = crypto.descriptor(shape)
    assert [part["alg"] for part in public["signatures"]] == ["ed25519", "ml-dsa-65"]
    assert all("signature" not in part for part in public["signatures"])
    assert crypto.descriptor(public) == public


@pytest.mark.parametrize("variant", ["empty", "missing", "one", "duplicate", "nested", "unknown", "reversed", "wrong-id", "bad-pq-size"])
def test_hybrid_invalid_structure_is_rejected_before_crypto(ed_signature, variant):
    value = _hybrid_shape(ed_signature)
    if variant == "empty":
        value["signatures"] = []
    elif variant == "missing":
        del value["signatures"]
    elif variant == "one":
        value["signatures"] = [ed_signature]
    elif variant == "duplicate":
        value["signatures"] = [ed_signature, ed_signature]
    elif variant == "nested":
        value["signatures"][1] = copy.deepcopy(value)
    elif variant == "unknown":
        value["signatures"][1]["alg"] = "unknown"
    elif variant == "reversed":
        value["signatures"].reverse()
    elif variant == "wrong-id":
        value["key_id"] = "0" * 64
    elif variant == "bad-pq-size":
        value["signatures"][1]["public_key"] = b64e(b"q")
    assert not crypto.verify(value, b"payload")
    with pytest.raises(ValueError):
        crypto.descriptor(value)


def test_hybrid_descriptor_does_not_substitute_for_a_signature(ed_signature):
    public = crypto.descriptor(_hybrid_shape(ed_signature))
    assert not crypto.verify(public, b"payload")


def test_pq_keyfiles_reject_unknown_fields_and_invalid_sizes():
    for value in [{}, {"alg": "ml-dsa-65", "secret_key": "", "public_key": ""},
                  {"alg": "hybrid", "ed25519": 1, "ml_dsa": {}}]:
        alg = "hybrid" if value.get("alg") == "hybrid" else "ml-dsa-65"
        with pytest.raises(ValueError):
            crypto.public_descriptor(alg, cjson(value))


def test_missing_native_runtime_fails_without_importing_or_downloading(monkeypatch):
    monkeypatch.setattr(crypto.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(crypto, "_native_oqs_available", lambda: False)
    with pytest.raises(RuntimeError, match="does not download"):
        crypto._require_oqs()


def test_private_key_created_with_private_permissions_and_no_clobber(tmp_path):
    path = tmp_path / "secret.key"
    crypto.write_private_key(path, b"secret")
    assert path.read_bytes() == b"secret"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        crypto.write_private_key(path, b"replaced")
    assert path.read_bytes() == b"secret"


@pytest.mark.parametrize("dangling", [True, False])
def test_private_key_refuses_destination_symlinks(tmp_path, dangling):
    target = tmp_path / "target.key"
    if not dangling:
        target.write_bytes(b"original")
    path = tmp_path / "link.key"
    path.symlink_to(target)
    with pytest.raises(OSError):
        crypto.write_private_key(path, b"secret")
    assert path.is_symlink()
    assert not target.exists() if dangling else target.read_bytes() == b"original"


def test_private_key_write_failure_removes_only_new_file(tmp_path, monkeypatch):
    path = tmp_path / "secret.key"
    def fail(*args):
        raise OSError("permission operation failed")
    monkeypatch.setattr(crypto.os, "fchmod", fail)
    with pytest.raises(OSError):
        crypto.write_private_key(path, b"secret")
    assert not path.exists()


@pytest.fixture
def real_pq_runtime():
    required = os.environ.get("SAIL_REQUIRE_PQ_TESTS") == "1"
    if importlib.util.find_spec("oqs") is None:
        if required:
            pytest.fail("SAIL_REQUIRE_PQ_TESTS=1 but liboqs-python is not installed")
        pytest.skip("optional real PQ test needs liboqs-python and liboqs")
    try:
        return crypto._require_oqs()
    except RuntimeError as exc:
        if required:
            pytest.fail(str(exc))
        pytest.skip(str(exc))


@pytest.mark.parametrize("alg", ["ml-dsa-65", "hybrid"])
def test_real_pq_roundtrip_and_each_hybrid_component_required(real_pq_runtime, alg):
    """Uses real native liboqs operations, with no mocked cryptography."""
    key = crypto.generate_keyfile(alg)
    signature = crypto.sign(alg, key, b"payload")
    assert crypto.verify(signature, b"payload")
    assert not crypto.verify(signature, b"changed")
    assert crypto.descriptor(signature) == crypto.public_descriptor(alg, key)
    if alg == "hybrid":
        for index in range(2):
            corrupted = copy.deepcopy(signature)
            component = corrupted["signatures"][index]
            raw = bytearray(b64d(component["signature"]))
            raw[0] ^= 1
            component["signature"] = b64e(bytes(raw))
            assert not crypto.verify(corrupted, b"payload")
        incomplete = copy.deepcopy(signature)
        incomplete["signatures"].pop()
        assert not crypto.verify(incomplete, b"payload")
