"""Regression tests for release integrity, policy binding and CLI workflows."""

import copy
import json
import os
from pathlib import Path

import pytest

from sail import commands, crypto, manifest, transparency
from sail.attestation import MINIMUM_TESTS
from sail.canonical import cjson, load_json, sha256_bytes
from sail.cli import main

DATE = "2026-10-24T12:00:00Z"
CARD = """# Test SAI model
## Intended use
Local regression testing of model release evidence.
## Out-of-scope use
This synthetic fixture is not suitable for production inference.
## Limitations
This fixture has no trained parameters or useful inference capability.
## Security evaluation
All evaluations below are fixture declarations for verification tests.
"""
SAIBOM = {"base_models": [], "datasets": [], "adapters": [], "dependencies": [],
          "data_provenance": "Synthetic regression fixture without training data.",
          "pipeline_ref": "https://github.com/Grigaliunas/SAIL-GPL/tree/main/sail/tests"}
TESTS = [{"name": name, "result": "not-applicable",
          "notes": "Synthetic fixture has no trained parameters or inference engine."}
         for name in MINIMUM_TESTS]


def make_model(root):
    model = root / "model"
    model.mkdir(parents=True)
    (model / "model.safetensors").write_bytes(b"synthetic weights")
    (model / "config.json").write_text('{"model_type":"fixture"}')
    (model / "MODEL_CARD.md").write_text(CARD)
    return model


def sign_t1(model, key, **options):
    kwargs = dict(model_name="fixture", model_version="1.0.0", key_path=key,
                  contact="https://github.com/Grigaliunas/SAIL-GPL/security/advisories/new",
                  policy_url="https://github.com/Grigaliunas/SAIL-GPL/blob/main/SECURITY.md",
                  created=DATE, aibom_overrides=copy.deepcopy(SAIBOM),
                  attestation_tests=copy.deepcopy(TESTS), issuer="fixture-publisher")
    kwargs.update(options)
    return commands.sign(model, **kwargs)


@pytest.fixture
def release(tmp_path):
    model, key = make_model(tmp_path), tmp_path / "signing.key"
    sign_t1(model, key)
    return model, key


def public(key, alg="ed25519"):
    return crypto.public_descriptor(alg, key.read_bytes())


def rebind(model, key):
    """Sign fixture mutations so schema checks are tested beyond hash failures."""
    old = load_json((model / "srm/manifest.json").read_bytes())
    man = manifest.build(model, model_name=old["model"]["name"],
                         model_version=old["model"]["version"], created=old["created"],
                         tier=old["tier"], signing=old["signing"])
    data = cjson(man)
    (model / "srm/manifest.json").write_bytes(data)
    env = {"_type": commands.SIGNATURE_TYPE, "schema_version": "2",
           "manifest_sha256": sha256_bytes(data),
           "signature": crypto.sign("ed25519", key.read_bytes(), data)}
    (model / "srm/model.sig").write_bytes(cjson(env))


def failed(rep, name):
    return any(n == name and not ok for n, ok, _ in rep.checks)


def test_roundtrip_and_trust_scope(release):
    model, key = release
    rep = commands.verify(model)
    assert rep.ok and not rep.identity_verified
    trusted = commands.verify(model, trusted_key=public(key), strict_issuer="fixture-publisher")
    assert trusted.ok and trusted.identity_verified


def test_ecdsa_roundtrip(tmp_path):
    model, key = make_model(tmp_path), tmp_path / "p256.key"
    sign_t1(model, key, alg="ecdsa-p256")
    assert commands.verify(model, trusted_key=public(key, "ecdsa-p256")).ok


def test_tamper_detected(release):
    model, _ = release
    (model / "config.json").write_text('{"tampered":true}')
    assert failed(commands.verify(model), "manifest-completeness")


def test_unsigned_extra_file_detected(release):
    model, _ = release
    (model / "injected.py").write_text("print('unsigned')")
    assert failed(commands.verify(model), "manifest-completeness")


@pytest.mark.parametrize("kind", ["file", "directory", "broken"])
def test_symlinks_cannot_hide_unsigned_content(release, tmp_path, kind):
    model, _ = release
    target = tmp_path / "external"
    if kind == "directory":
        target.mkdir()
        (target / "injected.py").write_text("unsigned")
    elif kind == "file":
        target.write_text("unsigned")
    (model / "link").symlink_to(target, target_is_directory=kind == "directory")
    assert failed(commands.verify(model), "safe-filesystem")


@pytest.mark.parametrize("filename", ["model.sig", "manifest.json", "saibom.json", "security-attestation.json"])
@pytest.mark.parametrize("value", [None, [], "invalid", 1, {"bad": True}])
def test_malformed_json_reports_failure_without_crash(release, filename, value):
    model, _ = release
    (model / "srm" / filename).write_bytes(cjson(value))
    assert not commands.verify(model).ok


def test_duplicate_json_keys_fail(release):
    model, _ = release
    (model / "srm/model.sig").write_text('{"signature":{},"signature":{}}')
    assert not commands.verify(model).ok


def test_empty_hybrid_forgery_fails(release):
    model, _ = release
    env = load_json((model / "srm/model.sig").read_bytes())
    env["signature"] = {"alg": "hybrid", "signatures": []}
    (model / "srm/model.sig").write_bytes(cjson(env))
    rep = commands.verify(model, pq_only=True, strict_issuer="fixture-publisher")
    assert not rep.ok and failed(rep, "signature")


def test_unsigned_policy_fields_cannot_override_actual_signature(release):
    model, key = release
    path = model / "srm/model.sig"
    env = load_json(path.read_bytes())
    env["issuer"] = "impersonated-publisher"
    env["crypto_agility"] = {"alg": "hybrid", "post_quantum": True}
    path.write_bytes(cjson(env))
    rep = commands.verify(model, trusted_key=public(key), pq_only=True,
                          strict_issuer="impersonated-publisher")
    assert failed(rep, "post-quantum-signature") and failed(rep, "strict-issuer")


def test_issuer_string_without_trusted_key_never_authenticates(release):
    model, _ = release
    assert failed(commands.verify(model, strict_issuer="fixture-publisher"), "strict-issuer")


def test_attacker_resigning_same_issuer_cannot_match_pinned_key(release, tmp_path):
    model, key = release
    pinned = public(key)
    sign_t1(model, tmp_path / "attacker.key")
    rep = commands.verify(model, trusted_key=pinned, strict_issuer="fixture-publisher")
    assert not rep.ok and not rep.identity_verified


def test_signed_policy_tamper_fails(release):
    model, _ = release
    path = model / "srm/manifest.json"
    man = load_json(path.read_bytes())
    man["signing"]["issuer"] = "changed"
    path.write_bytes(cjson(man))
    assert failed(commands.verify(model), "signature")


def test_trust_key_cannot_be_read_from_model_bundle(release):
    model, key = release
    path = model / "bundled-public.json"
    path.write_bytes(cjson(public(key)))
    assert not commands.verify(model, trusted_key=path).ok


def test_missing_explicit_tests_never_creates_success(tmp_path):
    model = make_model(tmp_path)
    with pytest.raises(ValueError, match="explicit adversarial"):
        sign_t1(model, tmp_path / "key.key", attestation_tests=None)
    assert not (model / "srm/security-attestation.json").exists()


def test_signed_attestation_without_results_rejected(release):
    model, key = release
    path = model / "srm/security-attestation.json"
    at = load_json(path.read_bytes())
    at["body"]["tests"] = [{"name": n} for n in MINIMUM_TESTS]
    at["body_sha256"] = sha256_bytes(cjson(at["body"]))
    at["signature"] = crypto.sign("ed25519", key.read_bytes(), cjson(at["body"]))
    path.write_bytes(cjson(at))
    rebind(model, key)
    assert failed(commands.verify(model), "attestation")


@pytest.mark.parametrize("filename,content,check", [
    ("MODEL_CARD.md", "", "model-card"),
    ("srm/SECURITY.md", "https://github.com/Grigaliunas/SAIL-GPL", "cvd-policy"),
])
def test_signed_incomplete_documents_rejected(release, filename, content, check):
    model, key = release
    (model / filename).write_text(content)
    rebind(model, key)
    assert failed(commands.verify(model), check)


def test_signed_incomplete_inventory_rejected(release):
    model, key = release
    path = model / "srm/saibom.json"
    ab = load_json(path.read_bytes())
    ab["pipeline"] = None
    path.write_bytes(cjson(ab))
    rebind(model, key)
    assert failed(commands.verify(model), "saibom")


def test_t3_cannot_be_signed_with_classical_algorithm(tmp_path):
    with pytest.raises(ValueError, match="T3 requires"):
        sign_t1(make_model(tmp_path), tmp_path / "key.key", tier="T3", independent=True)


def test_t3_cannot_be_mislabeled_after_signing(release):
    model, key = release
    path = model / "srm/manifest.json"
    man = load_json(path.read_bytes())
    man["tier"] = "T3"
    data = cjson(man)
    path.write_bytes(data)
    env = {"_type": commands.SIGNATURE_TYPE, "schema_version": "2",
           "manifest_sha256": sha256_bytes(data),
           "signature": crypto.sign("ed25519", key.read_bytes(), data)}
    (model / "srm/model.sig").write_bytes(cjson(env))
    rep = commands.verify(model)
    assert failed(rep, "post-quantum-signature")
    assert failed(rep, "transparency-inclusion")
    assert failed(rep, "trusted-signer")


def test_private_key_cannot_be_generated_inside_bundle(tmp_path):
    model = make_model(tmp_path)
    with pytest.raises(ValueError, match="outside the model"):
        sign_t1(model, model / "secret.key")
    assert not (model / "secret.key").exists()


def test_private_key_material_in_generic_filename_is_rejected(tmp_path):
    model = make_model(tmp_path)
    (model / "notes.txt").write_bytes(crypto.generate_keyfile("ed25519"))
    with pytest.raises(ValueError, match="private signing material"):
        sign_t1(model, tmp_path / "key.key")


def test_generated_keys_are_private_even_with_permissive_umask(tmp_path):
    previous = os.umask(0)
    try:
        model, key = make_model(tmp_path), tmp_path / "key.key"
        sign_t1(model, key)
    finally:
        os.umask(previous)
    assert key.stat().st_mode & 0o777 == 0o600


def test_keygen_does_not_overwrite_or_follow_links(tmp_path):
    key = tmp_path / "key.key"
    pub = tmp_path / "public.json"
    assert main(["keygen", "--out", str(key), "--public-out", str(pub)]) == 0
    original = key.read_bytes()
    assert main(["keygen", "--out", str(key)]) == 2
    assert key.read_bytes() == original
    link = tmp_path / "link.key"
    link.symlink_to(key)
    assert main(["keygen", "--out", str(link)]) == 2
    assert key.read_bytes() == original


@pytest.mark.parametrize("weights", ["weights.gguf", "pytorch_model.bin", "weights.onnx", "weights.pt", "part.safetensors"])
def test_audit_discovers_unsigned_model_formats(tmp_path, weights):
    (tmp_path / weights).write_bytes(b"unsigned")
    reports = commands.audit(tmp_path)
    assert len(reports) == 1 and not reports[0].ok


def test_audit_continues_after_malformed_model(release, tmp_path):
    model, _ = release
    bad = make_model(tmp_path / "bad")
    sign_t1(bad, tmp_path / "bad.key")
    (bad / "srm/model.sig").write_text("[]")
    reports = commands.audit(tmp_path)
    assert len(reports) == 2 and sum(r.ok for r in reports) == 1


def test_cli_json_is_machine_readable_on_malformed_evidence(release, capsys):
    model, _ = release
    (model / "srm/model.sig").write_text("[]")
    assert main(["verify", str(model), "--json"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["verified"] is False
    assert "compliant" not in output


def test_empty_and_nonexistent_audits_do_not_succeed(tmp_path):
    assert main(["audit", str(tmp_path), "--json"]) == 1
    assert main(["audit", str(tmp_path / "absent"), "--json"]) == 2


def test_manifest_duplicate_and_traversal_paths_rejected(release):
    model, _ = release
    man = load_json((model / "srm/manifest.json").read_bytes())
    man["files"].append(copy.deepcopy(man["files"][0]))
    assert any("duplicate" in p for p in manifest.check(model, man))
    man["files"][-1]["path"] = "../outside"
    assert any("path" in p for p in manifest.check(model, man))


def test_parent_signature_is_recorded_in_both_documents(tmp_path):
    model = make_model(tmp_path)
    sign_t1(model, tmp_path / "key.key", parent_signature_sha256="a" * 64)
    assert commands.verify(model).ok
    ab = load_json((model / "srm/saibom.json").read_bytes())
    assert ab["parent_signature_sha256"] == "a" * 64


def test_old_evaluator_report_cannot_be_replayed_for_changed_weights(release):
    model, key = release
    at = load_json((model / "srm/security-attestation.json").read_bytes())
    (model / "model.safetensors").write_bytes(b"different model, same name and version")
    with pytest.raises(ValueError, match="artifact digest"):
        sign_t1(model, key, attestation_document=at)
    rebind(model, key)
    rep = commands.verify(model)
    assert failed(rep, "attestation-binding")
    assert any(n == "signature" and ok for n, ok, _ in rep.checks)


def test_t3_complete_flow_with_real_pq(tmp_path):
    try:
        crypto._require_oqs()
    except RuntimeError:
        if os.environ.get("SAIL_REQUIRE_PQ_TESTS") == "1":
            pytest.fail("required real post-quantum runtime is unavailable")
        pytest.skip("optional real post-quantum runtime is unavailable")
    model, key = make_model(tmp_path), tmp_path / "publisher.key"
    evaluator = tmp_path / "evaluator.key"
    sign_t1(model, key, tier="T3", alg="ml-dsa-65", independent=True,
            evaluator="independent regression fixture", attestation_key_path=evaluator)
    pub, ev = public(key, "ml-dsa-65"), public(evaluator, "ml-dsa-65")
    rep = commands.verify(model, trusted_key=pub, trusted_evaluator_key=ev)
    assert failed(rep, "transparency-inclusion")
    data = (model / "srm/manifest.json").read_bytes()
    log_key = crypto.generate_keyfile("ed25519")
    log_pub = crypto.public_descriptor("ed25519", log_key)
    checkpoint = {"_type": transparency.CHECKPOINT_TYPE, "log_id": log_pub["key_id"],
                  "tree_size": 1, "root_hash": transparency.leaf_hash(data).hex(), "issued_at": DATE}
    proof = {"_type": transparency.RECEIPT_TYPE, "schema_version": "2",
             "manifest_sha256": sha256_bytes(data), "leaf_index": 0, "audit_path": [],
             "checkpoint": checkpoint, "signature": crypto.sign("ed25519", log_key, cjson(checkpoint))}
    commands.attach_log(model, proof, trusted_log_key=log_pub)
    assert commands.verify(model, trusted_key=pub, trusted_evaluator_key=ev, trusted_log_key=log_pub).ok
    assert not commands.verify(model, trusted_key=pub, trusted_log_key=log_pub).ok
    assert not commands.verify(model, trusted_evaluator_key=ev, trusted_log_key=log_pub).ok
    proof["checkpoint"]["root_hash"] = "0" * 64
    (model / "srm/transparency.json").write_bytes(cjson(proof))
    assert not commands.verify(model, trusted_key=pub, trusted_evaluator_key=ev, trusted_log_key=log_pub).ok


def test_audit_cannot_hide_unsigned_model_behind_directory_link(release, tmp_path):
    outside = tmp_path / "external-model"
    outside.mkdir()
    (outside / "weights.gguf").write_bytes(b"unsigned")
    wrapper = tmp_path / "wrapper"
    wrapper.mkdir()
    (wrapper / "unsigned-model").symlink_to(outside, target_is_directory=True)
    reports = commands.audit(wrapper)
    assert len(reports) == 1 and failed(reports[0], "safe-release-tree")


def test_artifact_inventory_sorts_relative_posix_strings(release):
    model, _ = release
    (model / "a").mkdir()
    (model / "a/b").write_text("data")
    (model / "a.txt").write_text("data")
    paths = [rel for rel, _ in manifest.iter_covered_files(model)]
    assert paths == sorted(paths)
    assert paths.index("a.txt") < paths.index("a/b")


def test_native_checkpoints_require_exact_utc_timestamp_syntax():
    assert not transparency.valid_timestamp("2026-10-24 12:00:00+00:00")
    assert not transparency.valid_timestamp("2026-10-24T12:00:00+01:00")
    assert transparency.valid_timestamp("2026-10-24T12:00:00Z")


def test_hybrid_component_cannot_impersonate_independent_evaluator(tmp_path):
    from sail import attestation
    try:
        crypto._require_oqs()
    except RuntimeError:
        if os.environ.get("SAIL_REQUIRE_PQ_TESTS") == "1":
            pytest.fail("required real post-quantum runtime is unavailable")
        pytest.skip("optional real post-quantum runtime is unavailable")
    model, key = make_model(tmp_path), tmp_path / "hybrid.key"
    keyfile = crypto.generate_keyfile("hybrid")
    crypto.write_private_key(key, keyfile)
    body = attestation.build(model_name="fixture", model_version="1.0.0", tier="T3",
                             tests=TESTS, evaluator="claimed independent evaluator",
                             independent=True, created=DATE,
                             artifact_sha256=manifest.artifact_digest(model))
    reused = attestation.sign_body(body, "ed25519", load_json(keyfile)["ed25519"].encode())
    with pytest.raises(ValueError, match="distinct independent"):
        sign_t1(model, key, alg="hybrid", tier="T3", attestation_document=reused)


def test_generated_metadata_does_not_leave_unsigned_appledouble_files(tmp_path):
    from sail.commands import _write
    destination = tmp_path / "public.json"
    _write(destination, b"{}")
    assert destination.read_bytes() == b"{}"
    assert not destination.with_name("._public.json").exists()


def test_optional_evaluator_pin_is_enforced_at_lower_tiers(release):
    model, key = release
    wrong_key = crypto.public_descriptor("ed25519", crypto.generate_keyfile("ed25519"))
    assert failed(commands.verify(model, trusted_key=public(key), trusted_evaluator_key=wrong_key), "trusted-evaluator")
    assert commands.verify(model, trusted_key=public(key), trusted_evaluator_key=public(key)).ok
