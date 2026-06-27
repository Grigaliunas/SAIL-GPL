"""High-level sign / verify / audit (SAIL-GPL §14.3)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import (
    AIBOM_NAME,
    ATTESTATION_NAME,
    MANIFEST_NAME,
    MODEL_CARD_NAME,
    SECURITY_NAME,
    SIGNATURE_NAME,
    SRM_DIR,
    aibom as aibom_mod,
    attestation as attest_mod,
    crypto,
    manifest as manifest_mod,
)
from .canonical import cjson, sha256_bytes

SIGNATURE_TYPE = "https://sail-gpl.org/srm/signature/v1"
_CONTACT_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+")


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass
class Report:
    target: Path
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.checks)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_key(alg: str, key_path: Optional[Path]) -> tuple[bytes, bool]:
    """Return (keyfile_bytes, persisted). Generates one if needed."""
    if key_path and key_path.exists():
        return key_path.read_bytes(), True
    keyfile = crypto.generate_keyfile(alg)
    if key_path:
        key_path.write_bytes(keyfile)
        return keyfile, True
    return keyfile, False  # ephemeral, not saved


# --------------------------------------------------------------------------- #
# sign
# --------------------------------------------------------------------------- #


def sign(model_dir: Path, *, model_name: str, model_version: str, tier: str = "T1",
         alg: str = crypto.DEFAULT_ALG, key_path: Optional[Path] = None,
         issuer: Optional[str] = None, contact: Optional[str] = None,
         policy_url: str = "https://example.org/security",
         created: Optional[str] = None, evaluator: str = "self-attestation",
         aibom_overrides: Optional[dict] = None,
         attestation_tests: Optional[list[dict]] = None,
         independent: bool = False,
         transparency_log: Optional[str] = None) -> dict:
    """Build the full SRM bundle in `model_dir/srm/` and return the envelope."""
    model_dir = model_dir.resolve()
    if not model_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {model_dir}")
    srm = model_dir / SRM_DIR
    srm.mkdir(exist_ok=True)

    keyfile, persisted = _resolve_key(alg, key_path)

    # 1. SECURITY.md (§7.6) -- write from contact, or keep an existing one.
    sec_path = srm / SECURITY_NAME
    if contact:
        _write(sec_path, attest_mod.security_md(contact, policy_url).encode("utf-8"))
    elif not sec_path.exists():
        raise ValueError("no SECURITY.md present and no --contact given (§7.6)")

    # 2. AIBOM (§7.2)
    ab = aibom_mod.build(model_name=model_name, model_version=model_version,
                         **(aibom_overrides or {}))
    _write(srm / AIBOM_NAME, cjson(ab))

    # 3. Attestation (§7.4), signed over its canonical body.
    tests = attestation_tests or [
        attest_mod.test(name, "pass", notes="self-attested (T1)")
        for name in attest_mod.MINIMUM_TESTS
    ]
    body = attest_mod.build(model_name=model_name, model_version=model_version,
                            tier=tier, tests=tests, evaluator=evaluator,
                            independent=independent, created=created)
    signed_attest = attest_mod.sign_body(body, alg, keyfile)
    _write(srm / ATTESTATION_NAME, cjson(signed_attest))

    # 4. Manifest over everything above (§7.1), then 5. detached signature.
    man = manifest_mod.build(model_dir, model_name=model_name,
                             model_version=model_version, created=created)
    man_bytes = cjson(man)
    _write(srm / MANIFEST_NAME, man_bytes)

    sig_part = crypto.sign(alg, keyfile, man_bytes)
    envelope = {
        "_type": SIGNATURE_TYPE,
        "spec_version": "SAIL-GPL-1.0",
        "manifest": MANIFEST_NAME,
        "manifest_sha256": sha256_bytes(man_bytes),
        "issuer": issuer or f"self-signed:{sig_part['key_id']}",
        "transparency_log": transparency_log,
        "signed_at": created,
        "crypto_agility": {
            "alg": alg,
            "post_quantum": crypto.is_pq(alg),
            "hybrid": alg.startswith(crypto.HYBRID),
        },
        **sig_part,
    }
    _write(srm / SIGNATURE_NAME, cjson(envelope))
    envelope["_key_persisted"] = persisted
    return envelope


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


def verify(model_dir: Path, *, pq_only: bool = False,
           strict_issuer: Optional[str] = None) -> Report:
    model_dir = model_dir.resolve()
    srm = model_dir / SRM_DIR
    rep = Report(target=model_dir)

    sig_path = srm / SIGNATURE_NAME
    man_path = srm / MANIFEST_NAME
    if not sig_path.exists() or not man_path.exists():
        rep.add("srm-present", False, f"missing {SRM_DIR}/{SIGNATURE_NAME} or {MANIFEST_NAME}")
        return rep
    rep.add("srm-present", True, "")

    envelope = _load_json(sig_path)
    man_bytes = man_path.read_bytes()

    # §7.1 signature chain: bytes -> declared hash -> valid signature.
    digest_ok = envelope.get("manifest_sha256") == sha256_bytes(man_bytes)
    rep.add("manifest-digest", digest_ok, "manifest_sha256 matches manifest.json")
    sig_ok = crypto.verify(envelope, man_bytes)
    rep.add("signature", sig_ok, f"alg={envelope.get('crypto_agility', {}).get('alg', envelope.get('alg'))}")

    # §7.1 completeness: every covered file present and unmodified, nothing extra.
    man = json.loads(man_bytes)
    problems = manifest_mod.check(model_dir, man)
    rep.add("manifest-completeness", not problems, "; ".join(problems))

    # §7.2 AIBOM
    ab_path = srm / AIBOM_NAME
    if ab_path.exists():
        ab_problems = aibom_mod.check(_load_json(ab_path))
        rep.add("aibom", not ab_problems, "; ".join(ab_problems))
    else:
        rep.add("aibom", False, f"missing {AIBOM_NAME}")

    # §7.3 model card
    rep.add("model-card", (model_dir / MODEL_CARD_NAME).exists(),
            f"{MODEL_CARD_NAME} present")

    # §7.4 attestation
    at_path = srm / ATTESTATION_NAME
    if at_path.exists():
        at_problems = attest_mod.check(_load_json(at_path))
        rep.add("attestation", not at_problems, "; ".join(at_problems))
    else:
        rep.add("attestation", False, f"missing {ATTESTATION_NAME}")

    # §7.6 coordinated vulnerability disclosure
    sec_path = srm / SECURITY_NAME
    if sec_path.exists() and _CONTACT_RE.search(sec_path.read_text(encoding="utf-8")):
        rep.add("cvd-contact", True, f"{SECURITY_NAME} has a contact")
    else:
        rep.add("cvd-contact", False, f"{SECURITY_NAME} missing or has no contact")

    # §7.5 / §8 modifiers
    if pq_only:
        alg = envelope.get("crypto_agility", {}).get("alg", envelope.get("alg", ""))
        rep.add("pq-only", crypto.is_pq(alg), f"alg={alg} is post-quantum")
    if strict_issuer is not None:
        rep.add("strict-issuer", envelope.get("issuer") == strict_issuer,
                f"issuer={envelope.get('issuer')!r}")
    return rep


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #


_MODEL_HINTS = ("config.json", "model.safetensors", MODEL_CARD_NAME)


def _looks_like_model(d: Path) -> bool:
    if (d / SRM_DIR).is_dir():
        return True
    return any((d / h).exists() for h in _MODEL_HINTS)


def discover(root: Path) -> list[Path]:
    """Find candidate model directories under `root`."""
    root = root.resolve()
    found = []
    if _looks_like_model(root):
        found.append(root)
    for d in sorted(p for p in root.rglob("*") if p.is_dir()):
        if d.name == SRM_DIR:
            continue
        if SRM_DIR in d.parts[len(root.parts):]:
            continue  # don't descend into srm/ internals
        if _looks_like_model(d):
            found.append(d)
    # de-dupe while keeping order
    seen, out = set(), []
    for d in found:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def audit(root: Path) -> list[Report]:
    return [verify(d) for d in discover(root)]
