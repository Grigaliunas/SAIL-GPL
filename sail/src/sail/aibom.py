"""SAI Bill of Materials (SAIBOM), the custom SAIL SRM v2 inventory.

This format is not an SPDX or CycloneDX serialization. Empty component lists
are explicit declarations rather than defaults inferred by the signer.
"""

from __future__ import annotations

import re
from typing import Optional

AIBOM_TYPE = "https://sail-gpl.org/srm/saibom/v2"
SCHEMA_VERSION = "2"
LICENSE_ID = "LicenseRef-SAIL-GPL-1.0"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_PLACEHOLDER_RE = re.compile(r"\b(?:TODO|TBD)\b", re.IGNORECASE)
_PLACEHOLDERS = {"unknown", "none", "n/a", "pending", "placeholder", "replace me", "not provided"}


def meaningful_text(value: object, *, minimum: int = 1) -> bool:
    """Reject absent or obvious template text without claiming semantic proof."""
    if not isinstance(value, str):
        return False
    text = value.strip()
    return (len(text) >= minimum and text.casefold().strip(". ") not in _PLACEHOLDERS
            and not _PLACEHOLDER_RE.search(text)
            and not re.fullmatch(r"[<\[]\s*(?:describe|insert|replace).*?[>\]]", text, re.I))


def _components(value: object, label: str, problems: list[str]) -> None:
    if not isinstance(value, list):
        problems.append(f"SAIBOM {label} must be an explicit list")
        return
    for index, component in enumerate(value):
        if not isinstance(component, dict):
            problems.append(f"SAIBOM {label}[{index}] must be an object")
            continue
        for key in ("name", "version", "license"):
            if not meaningful_text(component.get(key)):
                problems.append(f"SAIBOM {label}[{index}].{key} must be nonempty")


def build(*, model_name: str, model_version: str,
          base_models: Optional[list[dict]] = None,
          datasets: Optional[list[str]] = None,
          data_provenance: Optional[str] = None,
          adapters: Optional[list[dict]] = None,
          dependencies: Optional[list[dict]] = None,
          pipeline_ref: Optional[str] = None,
          licenses: Optional[list[str]] = None,
          parent_signature_sha256: Optional[str] = None) -> dict:
    """Build a validated inventory; all component lists must be supplied."""
    document = {
        "_type": AIBOM_TYPE,
        "schema_version": SCHEMA_VERSION,
        "name": f"{model_name}-{model_version}",
        "sai_model": {
            "name": model_name,
            "version": model_version,
            "baseModels": base_models,
            "adapters": adapters,
        },
        "data": {"datasets": datasets, "provenanceStatement": data_provenance},
        "dependencies": dependencies,
        "pipeline": pipeline_ref,
        "licenses": [LICENSE_ID] if licenses is None else licenses,
    }
    if parent_signature_sha256 is not None:
        document["parent_signature_sha256"] = parent_signature_sha256
    problems = check(document)
    if problems:
        raise ValueError("; ".join(problems))
    return document


def check(aibom: object) -> list[str]:
    """Return schema problems for any JSON value, without raising on bad types."""
    if not isinstance(aibom, dict):
        return ["SAIBOM must be an object"]
    problems: list[str] = []
    if aibom.get("_type") != AIBOM_TYPE or aibom.get("schema_version") != SCHEMA_VERSION:
        problems.append("SAIBOM must use the custom SAIL SRM v2 schema")
    model = aibom.get("sai_model")
    if not isinstance(model, dict):
        problems.append("SAIBOM sai_model must be an object")
        model = {}
    for key in ("name", "version"):
        if not meaningful_text(model.get(key)):
            problems.append(f"SAIBOM sai_model.{key} must be nonempty")
    if aibom.get("name") != f"{model.get('name')}-{model.get('version')}":
        problems.append("SAIBOM name must match its model name and version")
    _components(model.get("baseModels"), "sai_model.baseModels", problems)
    _components(model.get("adapters"), "sai_model.adapters", problems)
    _components(aibom.get("dependencies"), "dependencies", problems)
    data = aibom.get("data")
    if not isinstance(data, dict):
        problems.append("SAIBOM data must be an object")
        data = {}
    datasets = data.get("datasets")
    if not isinstance(datasets, list) or not all(meaningful_text(ref) for ref in datasets):
        problems.append("SAIBOM data.datasets must be an explicit list of nonempty references")
    if not meaningful_text(data.get("provenanceStatement"), minimum=12):
        problems.append("SAIBOM requires a meaningful data-provenance statement")
    if not meaningful_text(aibom.get("pipeline"), minimum=4):
        problems.append("SAIBOM requires a training or fine-tuning pipeline reference")
    licenses = aibom.get("licenses")
    if not isinstance(licenses, list) or not licenses or not all(meaningful_text(x) for x in licenses):
        problems.append("SAIBOM licenses must be a nonempty list of license identifiers")
    parent = aibom.get("parent_signature_sha256")
    if "parent_signature_sha256" in aibom and (not isinstance(parent, str) or not _DIGEST_RE.fullmatch(parent)):
        problems.append("SAIBOM parent_signature_sha256 must be a lowercase SHA-256 digest")
    return problems
