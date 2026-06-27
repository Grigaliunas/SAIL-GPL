"""End-to-end tests for the sail toolkit.

Run:  cd sail && PYTHONPATH=src python -m pytest -q
"""

import json
import struct
from pathlib import Path

import pytest

from sail import commands, crypto
from sail.attestation import MINIMUM_TESTS, test as mk_test


def make_model(root: Path) -> Path:
    m = root / "model"
    m.mkdir(parents=True)
    hdr = json.dumps({"__metadata__": {"note": "test"}}).encode()
    (m / "model.safetensors").write_bytes(struct.pack("<Q", len(hdr)) + hdr)
    (m / "config.json").write_text('{"model_type": "test"}')
    (m / "tokenizer.json").write_text('{"version": "1.0"}')
    (m / "MODEL_CARD.md").write_text("# card\nintended use\n")
    return m


def sign_t1(model: Path, key: Path, **kw):
    kw.setdefault("tier", "T1")
    kw.setdefault("aibom_overrides", {"data_provenance": "synthetic"})
    return commands.sign(
        model, model_name="test", model_version="1.0.0",
        key_path=key, contact="security@example.org", **kw,
    )


def test_sign_then_verify(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key")
    rep = commands.verify(model)
    assert rep.ok, rep.checks
    names = {n for n, _, _ in rep.checks}
    assert {"signature", "manifest-completeness", "aibom", "attestation", "cvd-contact"} <= names


def test_tamper_breaks_verify(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key")
    (model / "config.json").write_text('{"model_type": "test", "tampered": true}')
    rep = commands.verify(model)
    assert not rep.ok
    assert any(n == "manifest-completeness" and not ok for n, ok, _ in rep.checks)


def test_extra_unsigned_file_detected(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key")
    (model / "sneaky.bin").write_bytes(b"\x00\x01")
    rep = commands.verify(model)
    assert not rep.ok


def test_pq_only_rejects_classical(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key", alg="ed25519")
    rep = commands.verify(model, pq_only=True)
    assert not rep.ok
    assert any(n == "pq-only" and not ok for n, ok, _ in rep.checks)


def test_strict_issuer(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key", issuer="pki:CN=Acme")
    assert commands.verify(model, strict_issuer="pki:CN=Acme").ok
    assert not commands.verify(model, strict_issuer="pki:CN=Other").ok


def test_ecdsa_algorithm(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "k.key", alg="ecdsa-p256")
    assert commands.verify(model).ok


def test_tier_t2_requires_full_attestation(tmp_path):
    model = make_model(tmp_path)
    # Only one of the three minimum tests -> T2 must fail.
    sign_t1(model, tmp_path / "k.key", tier="T2",
            attestation_tests=[mk_test(MINIMUM_TESTS[0], "pass")])
    assert not commands.verify(model).ok


def test_audit_tree(tmp_path):
    good = make_model(tmp_path / "a")
    sign_t1(good, tmp_path / "k.key")
    bad = tmp_path / "a" / "bad"
    bad.mkdir()
    (bad / "config.json").write_text("{}")
    reports = commands.audit(tmp_path)
    by_ok = {str(r.target).endswith("model"): r.ok for r in reports}
    assert any(r.ok for r in reports)
    assert any(not r.ok for r in reports)


def test_signature_roundtrip_unit():
    kf = crypto.generate_keyfile("ed25519")
    part = crypto.sign("ed25519", kf, b"hello")
    assert crypto.verify(part, b"hello")
    assert not crypto.verify(part, b"hello!")
