"""Explicit signed SAI security attestations and release document validation.

SAIL SRM v2 records supplied evaluation evidence. Signing never performs tests
or creates a successful test result. A disclosed failure is valid metadata,
not a claim that a model is safe.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Optional
from urllib.parse import urlparse

from . import crypto
from .aibom import meaningful_text
from .canonical import cjson, sha256_bytes

ATTESTATION_TYPE = "https://sail-gpl.org/srm/attestation/v2"
SCHEMA_VERSION = "2"
MINIMUM_TESTS = ("prompt-injection", "training-data-extraction", "poisoning-backdoor")
TIER_REQUIRES_FULL_SET = {"T1": True, "T2": True, "T3": True}
TIERS = ("T1", "T2", "T3")
RESULTS = ("pass", "fail", "not-applicable")
SEVERITIES = ("info", "low", "medium", "high", "critical")


def valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except ValueError:
        return False


def _check_body(body: object) -> list[str]:
    if not isinstance(body, dict):
        return ["attestation body must be an object"]
    problems: list[str] = []
    if body.get("_type") != ATTESTATION_TYPE or body.get("schema_version") != SCHEMA_VERSION:
        problems.append("attestation must use the SAIL SRM v2 schema")
    model = body.get("model")
    if not isinstance(model, dict):
        problems.append("attestation model must be an object")
    else:
        for key in ("name", "version"):
            if not meaningful_text(model.get(key)):
                problems.append(f"attestation model.{key} must be nonempty")
    tier = body.get("tier")
    if not isinstance(tier, str) or tier not in TIERS:
        problems.append("attestation tier must be T1, T2 or T3")
    independent = body.get("independent_redteam")
    if type(independent) is not bool:
        problems.append("attestation independent_redteam must be a boolean")
    if tier == "T3" and independent is not True:
        problems.append("tier T3 requires an independent red-team attestation")
    if not meaningful_text(body.get("evaluator")):
        problems.append("attestation evaluator must be nonempty")
    digest = body.get("artifact_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        problems.append("attestation requires the evaluated artifact SHA-256")
    if not valid_timestamp(body.get("created")):
        problems.append("attestation created must be an ISO 8601 UTC timestamp")
    catalogs = body.get("catalogs")
    if not isinstance(catalogs, list) or not catalogs or not all(meaningful_text(x) for x in catalogs):
        problems.append("attestation catalogs must be a nonempty list of catalog references")
    tests = body.get("tests")
    if not isinstance(tests, list):
        problems.append("attestation tests must be an explicit list")
        return problems
    covered: set[str] = set()
    for index, entry in enumerate(tests):
        if not isinstance(entry, dict):
            problems.append(f"attestation tests[{index}] must be an object")
            continue
        name = entry.get("name")
        if not meaningful_text(name):
            problems.append(f"attestation tests[{index}].name must be nonempty")
        elif name in covered:
            problems.append(f"attestation has a duplicate test: {name}")
        else:
            covered.add(name)
        result = entry.get("result")
        if not isinstance(result, str) or result not in RESULTS:
            problems.append(f"attestation tests[{index}].result must be pass, fail or not-applicable")
        notes_ok = meaningful_text(entry.get("notes"), minimum=12)
        evidence_ok = meaningful_text(entry.get("evidence_ref"), minimum=4)
        if not notes_ok and not evidence_ok:
            problems.append(f"attestation tests[{index}] requires meaningful notes or an evidence_ref")
        if result == "not-applicable" and not notes_ok:
            problems.append(f"attestation tests[{index}] requires a reason for not-applicable")
        if "severity" in entry and (not isinstance(entry["severity"], str) or entry["severity"] not in SEVERITIES):
            problems.append(f"attestation tests[{index}].severity is invalid")
    missing = [name for name in MINIMUM_TESTS if name not in covered]
    if missing:
        problems.append(f"attestation missing minimum tests: {', '.join(missing)}")
    return problems


def build(*, model_name: str, model_version: str, tier: str,
          tests: list[dict], evaluator: str,
          catalogs: Optional[list[str]] = None,
          independent: bool = False, created: Optional[str] = None,
          artifact_sha256: Optional[str] = None) -> dict:
    """Return a validated unsigned body containing explicit supplied results."""
    body = {
        "_type": ATTESTATION_TYPE,
        "schema_version": SCHEMA_VERSION,
        "model": {"name": model_name, "version": model_version},
        "tier": tier,
        "evaluator": evaluator,
        "artifact_sha256": artifact_sha256,
        "independent_redteam": independent,
        "catalogs": ["OWASP-LLM-Top-10", "MITRE-ATLAS", "CoSAI-Risk-Map"] if catalogs is None else catalogs,
        "created": created,
        "tests": tests,
    }
    problems = _check_body(body)
    if problems:
        raise ValueError("; ".join(problems))
    return body


def test(name: str, result: str, *, severity: str = "info", notes: str = "", evidence_ref: Optional[str] = None) -> dict:
    entry = {"name": name, "result": result, "severity": severity, "notes": notes}
    if evidence_ref is not None:
        entry["evidence_ref"] = evidence_ref
    return entry


def sign_body(body: dict, alg: str, keyfile: bytes) -> dict:
    problems = _check_body(body)
    if problems:
        raise ValueError("; ".join(problems))
    payload = cjson(body)
    sig = crypto.sign(alg, keyfile, payload)
    return {"body": body, "body_sha256": sha256_bytes(payload), "signature": sig}


def check(attestation: object) -> list[str]:
    """Validate structure before cryptography, including arbitrary JSON types."""
    if not isinstance(attestation, dict):
        return ["attestation must be an object"]
    body, sig = attestation.get("body"), attestation.get("signature")
    problems = _check_body(body)
    if not isinstance(sig, dict):
        problems.append("attestation signature must be an object")
    if problems:
        return problems
    try:
        payload = cjson(body)
    except (TypeError, ValueError, UnicodeError):
        return ["attestation body cannot be canonically encoded"]
    if attestation.get("body_sha256") != sha256_bytes(payload):
        problems.append("attestation body_sha256 does not match body")
    try:
        signature_ok = crypto.verify(sig, payload)
    except (TypeError, ValueError, KeyError, AttributeError):
        signature_ok = False
    if not signature_ok:
        problems.append("attestation signature is invalid")
    return problems


def _sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        heading = re.fullmatch(r"\s*#{1,6}\s+(.+?)\s*#*\s*", line)
        if heading:
            current = heading.group(1).strip().casefold().replace("out of scope", "out-of-scope")
            sections.setdefault(current, "")
        elif current:
            sections[current] += line + "\n"
    return sections


def check_model_card(text: object) -> list[str]:
    if not isinstance(text, str):
        return ["model card must be UTF-8 text"]
    sections = _sections(text)
    problems = []
    for name in ("intended use", "out-of-scope use", "limitations", "security evaluation"):
        if not meaningful_text(sections.get(name), minimum=12):
            problems.append(f"model card requires a non-placeholder '{name}' section")
    return problems


def _real_host(host: Optional[str]) -> bool:
    if not host or "." not in host:
        return False
    host = host.casefold().rstrip(".")
    return (host not in {"example.com", "example.org", "example.net"}
            and not host.endswith((".example", ".invalid", ".localhost", ".test"))
            and not any(host.endswith("." + base) for base in ("example.com", "example.org", "example.net")))


def _valid_contact(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith("https://"):
        return _valid_policy(value)
    email = value.removeprefix("mailto:").strip()
    match = re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+)", email)
    return bool(match and _real_host(match.group(1)))


def _valid_policy(value: object) -> bool:
    if not isinstance(value, str) or any(c.isspace() for c in value):
        return False
    try:
        url = urlparse(value)
        return url.scheme == "https" and _real_host(url.hostname) and not url.username and not url.password
    except ValueError:
        return False


def check_security_md(text: object) -> list[str]:
    """Require explicit contact and policy fields plus a meaningful CVD process."""
    if not isinstance(text, str):
        return ["security policy must be UTF-8 text"]
    fields = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(?:[-*]\s*)?(?:\*\*)?(Contact|Policy):(?:\*\*)?\s*(.*?)\s*", line, re.I)
        if match:
            key = match.group(1).casefold()
            if key in fields:
                return [f"security policy has duplicate {key} fields"]
            fields[key] = match.group(2)
    problems = []
    if not _valid_contact(fields.get("contact")):
        problems.append("security policy requires an explicit non-placeholder Contact email or HTTPS URL")
    if not _valid_policy(fields.get("policy")):
        problems.append("security policy requires an explicit non-placeholder HTTPS Policy URL")
    if not meaningful_text(_sections(text).get("cvd process"), minimum=40):
        problems.append("security policy requires a meaningful 'CVD process' section")
    return problems


SECURITY_MD_TEMPLATE = """\
# Security Policy

This SAI Model Artifact is released under SAIL-GPL v1.0.

## Reporting a vulnerability

- **Contact:** {contact}
- **Policy:** {policy_url}

## CVD process

Report vulnerabilities privately using the contact above. The steward will
acknowledge reports, investigate their impact, coordinate fixes and agree a
public disclosure date with the reporter. Material security changes require
a refreshed release, evaluation disclosure and signed release metadata.

Derivative model stewards must preserve the inherited disclosure obligations
and publish their own working contact and process.
"""


def security_md(contact: str, policy_url: str) -> str:
    document = SECURITY_MD_TEMPLATE.format(contact=contact, policy_url=policy_url)
    problems = check_security_md(document)
    if problems:
        raise ValueError("; ".join(problems))
    return document
