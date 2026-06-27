"""Signed adversarial-security attestation (SAIL-GPL §7.4) and the minimum
test set that scales with deployment tier (§8).

The attestation has a `body` (the claims) and a detached `signature` over the
canonical body bytes, so it can be verified independently of the manifest.
"""

from __future__ import annotations

from typing import Optional

from . import crypto
from .canonical import cjson, sha256_bytes

ATTESTATION_TYPE = "https://sail-gpl.org/srm/attestation/v1"

# §7.4 minimum coverage, drawn from OWASP LLM Top 10 / MITRE ATLAS / CoSAI.
MINIMUM_TESTS = ("prompt-injection", "training-data-extraction", "poisoning-backdoor")

# §8: which obligations a tier carries for §7.4.
TIER_REQUIRES_FULL_SET = {"T1": False, "T2": True, "T3": True}
TIERS = ("T1", "T2", "T3")


def build(*, model_name: str, model_version: str, tier: str,
          tests: list[dict], evaluator: str,
          catalogs: Optional[list[str]] = None,
          independent: bool = False, created: Optional[str] = None) -> dict:
    """Return the attestation *body* (unsigned). Sign it with `sign_body`."""
    return {
        "_type": ATTESTATION_TYPE,
        "model": {"name": model_name, "version": model_version},
        "tier": tier,
        "evaluator": evaluator,
        "independent_redteam": independent,
        "catalogs": catalogs or ["OWASP-LLM-Top-10", "MITRE-ATLAS", "CoSAI-Risk-Map"],
        "created": created,
        "tests": tests,
    }


def test(name: str, result: str, *, severity: str = "info", notes: str = "") -> dict:
    return {"name": name, "result": result, "severity": severity, "notes": notes}


def sign_body(body: dict, alg: str, keyfile: bytes) -> dict:
    payload = cjson(body)
    sig = crypto.sign(alg, keyfile, payload)
    return {"body": body, "body_sha256": sha256_bytes(payload), "signature": sig}


def check(attestation: dict) -> list[str]:
    """Structural + cryptographic checks on a signed attestation."""
    problems = []
    body = attestation.get("body")
    sig = attestation.get("signature")
    if not isinstance(body, dict) or not isinstance(sig, dict):
        return ["attestation missing body or signature"]

    payload = cjson(body)
    if attestation.get("body_sha256") != sha256_bytes(payload):
        problems.append("attestation body_sha256 does not match body")
    if not crypto.verify(sig, payload):
        problems.append("attestation signature is invalid")

    tier = body.get("tier")
    if tier not in TIERS:
        problems.append(f"attestation tier invalid: {tier!r}")
    covered = {t.get("name") for t in body.get("tests", [])}
    missing = [t for t in MINIMUM_TESTS if t not in covered]
    if missing:
        problems.append(f"attestation missing minimum tests: {', '.join(missing)}")
    if TIER_REQUIRES_FULL_SET.get(tier) and len(covered) < len(MINIMUM_TESTS):
        problems.append(f"tier {tier} requires the full minimum test set (§7.4/§8)")
    if tier == "T3" and not body.get("independent_redteam"):
        problems.append("tier T3 requires an independent red-team (§8)")
    return problems


SECURITY_MD_TEMPLATE = """\
# Security Policy

This Model Artifact is released under SAIL-GPL v1.0. Per §7.6, security issues
are handled through coordinated vulnerability disclosure.

## Reporting a vulnerability

- **Contact:** {contact}
- **Policy:** {policy_url}

Please report privately and allow a reasonable time for a fix before public
disclosure. We follow recognized coordinated-disclosure practice (e.g. the
CoSAI AI incident-response guidance).

This contact and policy propagate to every Derivative Model (§7.6, §7.8).
"""


def security_md(contact: str, policy_url: str) -> str:
    return SECURITY_MD_TEMPLATE.format(contact=contact, policy_url=policy_url)
