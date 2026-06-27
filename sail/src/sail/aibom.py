"""AI Bill of Materials (SAIL-GPL §7.2).

A minimal, machine-readable SPDX-3.0-AI-flavoured document declaring the
model's upstream materials: base model(s), datasets or a data-provenance
statement, applied adapters, and key dependencies. This is intentionally a
small, valid skeleton you extend per release — not a full SPDX implementation.
"""

from __future__ import annotations

from typing import Optional

AIBOM_TYPE = "https://spdx.org/rdf/3.0.1/ai-profile"


def build(*, model_name: str, model_version: str,
          base_models: Optional[list[str]] = None,
          datasets: Optional[list[str]] = None,
          data_provenance: Optional[str] = None,
          adapters: Optional[list[str]] = None,
          dependencies: Optional[list[str]] = None,
          pipeline_ref: Optional[str] = None,
          licenses: Optional[list[str]] = None) -> dict:
    return {
        "spdxVersion": "SPDX-3.0",
        "profile": ["core", "ai", "software"],
        "_type": AIBOM_TYPE,
        "name": f"{model_name}-{model_version}",
        "ai_model": {
            "name": model_name,
            "version": model_version,
            "baseModels": base_models or [],
            "adapters": adapters or [],
        },
        "data": {
            "datasets": datasets or [],
            # §7.2 accepts a documented data-provenance statement in lieu of a
            # full dataset list.
            "provenanceStatement": data_provenance,
        },
        "dependencies": dependencies or [],
        "pipeline": pipeline_ref,
        "licenses": licenses or ["SAIL-GPL-1.0"],
    }


def check(aibom: dict) -> list[str]:
    problems = []
    if not aibom.get("ai_model", {}).get("name"):
        problems.append("AIBOM missing ai_model.name")
    data = aibom.get("data", {})
    if not data.get("datasets") and not data.get("provenanceStatement"):
        problems.append("AIBOM declares neither datasets nor a data-provenance statement")
    if not aibom.get("licenses"):
        problems.append("AIBOM missing license declaration")
    return problems
