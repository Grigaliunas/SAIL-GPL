"""Build and verify native SAIL SRM v2 technical release evidence."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import (AIBOM_NAME, ATTESTATION_NAME, FORMAT_VERSION, MANIFEST_NAME,
               MODEL_CARD_NAME, SECURITY_NAME, SIGNATURE_NAME, SRM_DIR,
               TRANSPARENCY_NAME, aibom, attestation, crypto, manifest, transparency)
from .canonical import cjson, load_json, sha256_bytes

SIGNATURE_TYPE = "https://sail-gpl.org/srm/signature/v2"
SCOPE = "SAIL SRM v2 integrity and required technical evidence; not legal or safety certification"


@dataclass
class Report:
    target: Path
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    identity_verified: bool = False

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, bool(ok), detail))

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(ok for _, ok, _ in self.checks)


def _write(path: Path, data: bytes) -> None:
    """Replace a regular metadata file atomically without following file links."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError(f"refusing symbolic-link metadata destination: {path.name}")
    fd, temporary = tempfile.mkstemp(prefix=".sail-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(temporary, path)
        # macOS can materialize AppleDouble metadata on external filesystems.
        # Remove only the recognized OS sidecar for this newly written file.
        # Sidecars are never silently ignored by the manifest verifier.
        sidecar = path.with_name("._" + path.name)
        if sys.platform == "darwin" and sidecar.is_file() and not sidecar.is_symlink():
            with sidecar.open("rb") as metadata:
                is_appledouble = metadata.read(4) == b"\x00\x05\x16\x07"
            if is_appledouble:
                sidecar.unlink()
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_json(path: Path):
    return load_json(path.read_bytes())


def _trust(value, model_dir: Path):
    if value is None:
        return None
    if isinstance(value, (str, Path)):
        path = Path(value).resolve()
        if path.is_relative_to(model_dir):
            raise ValueError("trusted verification keys must be supplied outside the model bundle")
        value = _load_json(path)
    return crypto.descriptor(value)


def _key_ids(public: dict) -> set[str]:
    """Role separation applies to each key, including hybrid components."""
    return ({part["key_id"] for part in public["signatures"]}
            if public["alg"] == "hybrid" else {public["key_id"]})


def _resolve_key(alg: str, key_path: Optional[Path]) -> tuple[bytes, bool]:
    if key_path is not None:
        if key_path.is_symlink():
            raise ValueError("private key path must not be a symbolic link")
        if key_path.exists():
            if not key_path.is_file():
                raise ValueError("private key must be a regular file")
            if os.name == "posix" and key_path.stat().st_mode & 0o077:
                raise ValueError("private key permissions must be 0600 or stricter")
            return key_path.read_bytes(), True
    data = crypto.generate_keyfile(alg)
    if key_path is not None:
        crypto.write_private_key(key_path, data)
        return data, True
    return data, False


def _require_clean_tree(model_dir: Path):
    problems = manifest.inspect_tree(model_dir)
    if not problems:
        for rel, path in manifest.iter_covered_files(model_dir):
            if manifest.contains_private_key(path):
                problems.append(f"private signing material must not be distributed: {rel}")
    if problems:
        raise ValueError("; ".join(problems))


def sign(model_dir: Path, *, model_name: str, model_version: str, tier: str = "T1",
         alg: str = crypto.DEFAULT_ALG, key_path: Optional[Path] = None,
         issuer: Optional[str] = None, contact: Optional[str] = None,
         policy_url: Optional[str] = None, created: Optional[str] = None,
         evaluator: str = "self-attestation", aibom_overrides: Optional[dict] = None,
         attestation_tests: Optional[list[dict]] = None, independent: bool = False,
         attestation_key_path: Optional[Path] = None,
         attestation_document: Optional[dict] = None,
         parent_signature_sha256: Optional[str] = None) -> dict:
    model_dir = model_dir.resolve()
    _require_clean_tree(model_dir)
    if not all(isinstance(v, str) and v.strip() for v in (model_name, model_version)):
        raise ValueError("model name and version are required")
    if tier not in attestation.TIERS:
        raise ValueError("tier must be T1, T2 or T3")
    if tier == "T3" and not crypto.is_pq(alg):
        raise ValueError("T3 requires an ML-DSA-65 or hybrid release signature")
    created = created or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not transparency.valid_timestamp(created):
        raise ValueError("created must be a UTC timestamp")
    for key in (key_path, attestation_key_path):
        if key is not None and key.resolve().is_relative_to(model_dir):
            raise ValueError("private keys must be stored outside the model bundle")
    card = model_dir / MODEL_CARD_NAME
    card_problems = attestation.check_model_card(card.read_text(encoding="utf-8")) if card.is_file() else ["missing MODEL_CARD.md"]
    if card_problems:
        raise ValueError("; ".join(card_problems))
    srm = model_dir / SRM_DIR
    sec_path = srm / SECURITY_NAME
    if contact is not None:
        if not policy_url:
            raise ValueError("an explicit HTTPS policy URL is required with a contact")
        security = attestation.security_md(contact, policy_url)
    elif sec_path.is_file():
        security = sec_path.read_text(encoding="utf-8")
    else:
        raise ValueError("an explicit security contact and policy are required")
    security_problems = attestation.check_security_md(security)
    if security_problems:
        raise ValueError("; ".join(security_problems))
    if not isinstance(aibom_overrides, dict):
        raise ValueError("explicit SAIBOM inputs are required")
    ab = aibom.build(model_name=model_name, model_version=model_version,
                     parent_signature_sha256=parent_signature_sha256, **aibom_overrides)
    problems = aibom.check(ab)
    if problems:
        raise ValueError("; ".join(problems))
    if attestation_document is None and attestation_tests is None:
        raise ValueError("explicit adversarial test reports are required; no tests run automatically")
    evaluated_artifact = manifest.artifact_digest(model_dir)
    keyfile, persisted = _resolve_key(alg, key_path)
    public = crypto.public_descriptor(alg, keyfile)
    signing = {"alg": public["alg"], "key_id": public["key_id"],
               "issuer": issuer or f"self-signed:{public['key_id']}"}
    if not isinstance(signing["issuer"], str) or not signing["issuer"].strip():
        raise ValueError("issuer must be a nonempty string")
    if attestation_document is None:
        body = attestation.build(model_name=model_name, model_version=model_version,
                                 tier=tier, tests=attestation_tests, evaluator=evaluator,
                                 independent=independent, created=created,
                                 artifact_sha256=evaluated_artifact)
        eval_keyfile = keyfile
        if attestation_key_path is not None:
            eval_keyfile, _ = _resolve_key(alg, attestation_key_path)
        signed_attest = attestation.sign_body(body, alg, eval_keyfile)
    else:
        signed_attest = attestation_document
    problems = attestation.check(signed_attest)
    if problems:
        raise ValueError("; ".join(problems))
    body = signed_attest["body"]
    if (body["model"] != {"name": model_name, "version": model_version}
            or body["tier"] != tier or body["artifact_sha256"] != evaluated_artifact):
        raise ValueError("attestation artifact digest, model identity and tier must match this release")
    if tier == "T3" and not _key_ids(crypto.descriptor(signed_attest["signature"])).isdisjoint(_key_ids(public)):
        raise ValueError("T3 requires a distinct independent evaluator signing key")
    _write(sec_path, security.encode("utf-8"))
    _write(srm / AIBOM_NAME, cjson(ab))
    _write(srm / ATTESTATION_NAME, cjson(signed_attest))
    man = manifest.build(model_dir, model_name=model_name, model_version=model_version,
                         created=created, signing=signing, tier=tier,
                         parent_signature_sha256=parent_signature_sha256)
    man_bytes = cjson(man)
    envelope = {"_type": SIGNATURE_TYPE, "schema_version": FORMAT_VERSION,
                "manifest_sha256": sha256_bytes(man_bytes),
                "signature": crypto.sign(alg, keyfile, man_bytes)}
    _write(srm / MANIFEST_NAME, man_bytes)
    _write(srm / SIGNATURE_NAME, cjson(envelope))
    # A previous receipt belongs to the previous manifest and must be renewed.
    (srm / TRANSPARENCY_NAME).unlink(missing_ok=True)
    return {**envelope, "_key_persisted": persisted, "_signing": signing}


def verify(model_dir: Path, *, pq_only: bool = False, strict_issuer: Optional[str] = None,
           trusted_key=None, trusted_evaluator_key=None, trusted_log_key=None) -> Report:
    model_dir = model_dir.resolve()
    rep = Report(target=model_dir)
    try:
        _verify(model_dir, rep, pq_only, strict_issuer, trusted_key,
                trusted_evaluator_key, trusted_log_key)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError) as exc:
        rep.add("readable-structured-evidence", False, f"invalid or unreadable release evidence: {exc}")
    return rep


def _verify(model_dir, rep, pq_only, strict_issuer, trusted_key, trusted_evaluator_key, trusted_log_key):
    tree_problems = manifest.inspect_tree(model_dir)
    rep.add("safe-filesystem", not tree_problems, "; ".join(tree_problems))
    if tree_problems:
        return
    srm = model_dir / SRM_DIR
    sig_path, man_path = srm / SIGNATURE_NAME, srm / MANIFEST_NAME
    if not sig_path.is_file() or not man_path.is_file():
        rep.add("srm-present", False, "missing manifest.json or model.sig")
        return
    envelope = _load_json(sig_path)
    man_bytes = man_path.read_bytes()
    man = load_json(man_bytes)
    if (not isinstance(envelope, dict) or envelope.get("_type") != SIGNATURE_TYPE
            or envelope.get("schema_version") != FORMAT_VERSION):
        rep.add("srm-format", False, "unsupported signature format; re-sign using SAIL SRM v2")
        return
    rep.add("srm-format", True, "native SAIL SRM v2")
    rep.add("manifest-canonical", cjson(man) == man_bytes, "manifest uses the specified canonical encoding")
    rep.add("manifest-digest", envelope.get("manifest_sha256") == sha256_bytes(man_bytes))
    signature = envelope.get("signature")
    sig_ok = crypto.verify(signature, man_bytes)
    rep.add("signature", sig_ok, "release manifest signature")
    public = crypto.descriptor(signature)
    problems = manifest.check(model_dir, man)
    rep.add("manifest-completeness", not problems, "; ".join(problems))
    model, tier, signing = man.get("model"), man.get("tier"), man.get("signing")
    identity_ok = (isinstance(model, dict) and all(isinstance(model.get(k), str) and model[k].strip() for k in ("name", "version")))
    rep.add("model-identity", identity_ok)
    rep.add("release-tier", isinstance(tier, str) and tier in attestation.TIERS)
    rep.add("release-timestamp", transparency.valid_timestamp(man.get("created")))
    signing_ok = (isinstance(signing, dict) and signing.get("alg") == public["alg"]
                  and signing.get("key_id") == public["key_id"]
                  and isinstance(signing.get("issuer"), str) and bool(signing["issuer"].strip()))
    rep.add("signed-policy", signing_ok, "algorithm, key and issuer are bound by the manifest signature")
    trusted = _trust(trusted_key, model_dir)
    if trusted is not None or tier == "T3":
        rep.identity_verified = sig_ok and public == trusted and signing_ok
        rep.add("trusted-signer", rep.identity_verified, "signer matches the externally supplied verification key")
    if strict_issuer is not None:
        rep.add("strict-issuer", rep.identity_verified and signing_ok and signing["issuer"] == strict_issuer,
                "issuer matching requires an externally trusted signer key")
    if pq_only or tier == "T3":
        rep.add("post-quantum-signature", sig_ok and crypto.is_pq(public["alg"]), f"verified algorithm: {public['alg']}")
    ab = _load_json(srm / AIBOM_NAME)
    problems = aibom.check(ab)
    rep.add("saibom", not problems, "; ".join(problems))
    if not problems:
        rep.add("saibom-model", ab["sai_model"]["name"] == model.get("name") and ab["sai_model"]["version"] == model.get("version"))
        parent = man.get("derived_from", {}).get("parent_signature_sha256")
        rep.add("derivation-link", ab.get("parent_signature_sha256") == parent,
                "parent signature reference agrees across release metadata")
    card_problems = attestation.check_model_card((model_dir / MODEL_CARD_NAME).read_text(encoding="utf-8"))
    rep.add("model-card", not card_problems, "; ".join(card_problems))
    at = _load_json(srm / ATTESTATION_NAME)
    problems = attestation.check(at)
    rep.add("attestation", not problems, "; ".join(problems))
    if not problems:
        rep.add("attestation-binding", at["body"]["model"] == model and at["body"]["tier"] == tier
                and at["body"]["artifact_sha256"] == manifest.artifact_digest(model_dir),
                "evaluation is bound to this artifact's files, model version and release tier")
        evaluator = _trust(trusted_evaluator_key, model_dir)
        actual = crypto.descriptor(at["signature"])
        if evaluator is not None:
            rep.add("trusted-evaluator", actual == evaluator,
                    "evaluation signer matches the externally supplied evaluator key")
        if tier == "T3":
            independent = (evaluator is not None and actual == evaluator
                           and _key_ids(actual).isdisjoint(_key_ids(public))
                           and at["body"]["independent_redteam"] is True)
            rep.add("independent-evaluator", independent, "T3 requires a distinct, externally trusted evaluator key")
    sec_problems = attestation.check_security_md((srm / SECURITY_NAME).read_text(encoding="utf-8"))
    rep.add("cvd-policy", not sec_problems, "; ".join(sec_problems))
    receipt = srm / TRANSPARENCY_NAME
    if tier == "T3" or receipt.exists():
        if receipt.is_file():
            log_key = _trust(trusted_log_key, model_dir)
            problems = transparency.check(_load_json(receipt), man_bytes, log_key)
            if tier == "T3" and log_key is not None:
                evaluator_public = crypto.descriptor(at["signature"])
                if not _key_ids(log_key).isdisjoint(_key_ids(public) | _key_ids(evaluator_public)):
                    problems.append("T3 publisher, evaluator and log signing key material must be distinct")
        else:
            problems = ["T3 requires srm/transparency.json with a signed inclusion receipt"]
        rep.add("transparency-inclusion", not problems, "; ".join(problems))


def attach_log(model_dir: Path, proof: dict, *, trusted_log_key) -> None:
    model_dir = model_dir.resolve()
    _require_clean_tree(model_dir)
    man_bytes = (model_dir / SRM_DIR / MANIFEST_NAME).read_bytes()
    log_key = _trust(trusted_log_key, model_dir)
    problems = transparency.check(proof, man_bytes, log_key)
    if problems:
        raise ValueError("; ".join(problems))
    man = load_json(man_bytes)
    if man.get("tier") == "T3":
        publisher = crypto.descriptor(_load_json(model_dir / SRM_DIR / SIGNATURE_NAME)["signature"])
        evaluator = crypto.descriptor(_load_json(model_dir / SRM_DIR / ATTESTATION_NAME)["signature"])
        if not _key_ids(log_key).isdisjoint(_key_ids(publisher) | _key_ids(evaluator)):
            raise ValueError("T3 log signing key material must be distinct from publisher and evaluator keys")
    _write(model_dir / SRM_DIR / TRANSPARENCY_NAME, cjson(proof))


_MODEL_SUFFIXES = {".gguf", ".safetensors", ".pt", ".pth", ".onnx", ".h5", ".tflite", ".bin"}


def _looks_like_model(directory: Path) -> bool:
    return ((directory / SRM_DIR).exists() or (directory / MODEL_CARD_NAME).exists()
            or (directory / "config.json").exists()
            or any(p.suffix.lower() in _MODEL_SUFFIXES for p in directory.iterdir() if p.is_file()))


def discover(root: Path) -> list[Path]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("audit path must be an existing directory")
    found = [root] if _looks_like_model(root) else []
    for directory in sorted(root.rglob("*")):
        if (directory.is_dir() and not directory.is_symlink()
                and SRM_DIR not in directory.relative_to(root).parts
                and _looks_like_model(directory)):
            found.append(directory)
    return found


def audit(root: Path, **verify_options) -> list[Report]:
    directories = discover(root)
    reports = [verify(directory, **verify_options) for directory in directories]
    # Unsafe siblings must not disappear merely because they lack model hints.
    problems = manifest.inspect_tree(root.resolve())
    if problems and root.resolve() not in directories:
        rep = Report(root.resolve())
        rep.add("safe-release-tree", False, "; ".join(problems))
        reports.append(rep)
    return reports
