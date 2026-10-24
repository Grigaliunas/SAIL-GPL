"""Security metadata rejects missing, malformed and invented evidence."""

from copy import deepcopy

import pytest

from sail import aibom, attestation, crypto

DATE = "2026-10-24T12:00:00Z"


def inventory(**overrides):
    values = dict(
        model_name="audit-model", model_version="1.0", base_models=[],
        datasets=[], data_provenance="Weights were trained only on generated synthetic records.",
        adapters=[], dependencies=[], pipeline_ref="git:https://github.com/maintainers/project@abc123",
    )
    values.update(overrides)
    return aibom.build(**values)


def results():
    return [attestation.test(name, "fail", notes="The supplied evaluation found a reproducible weakness.")
            for name in attestation.MINIMUM_TESTS]


def body(**overrides):
    values = dict(model_name="audit-model", model_version="1.0", tier="T1",
                  tests=results(), evaluator="release evaluator", created=DATE,
                  artifact_sha256="a" * 64)
    values.update(overrides)
    return attestation.build(**values)


def test_explicit_empty_material_lists_and_disclosed_failed_tests_are_valid():
    assert aibom.check(inventory()) == []
    assert "spdxVersion" not in inventory()
    assert inventory()["licenses"] == ["LicenseRef-SAIL-GPL-1.0"]
    key = crypto.generate_keyfile("ed25519")
    signed = attestation.sign_body(body(), "ed25519", key)
    assert attestation.check(signed) == []
    assert all(entry["result"] == "fail" for entry in signed["body"]["tests"])


@pytest.mark.parametrize("field", ["base_models", "datasets", "adapters", "dependencies"])
def test_material_lists_cannot_be_implicitly_inferred(field):
    with pytest.raises(ValueError):
        inventory(**{field: None})


@pytest.mark.parametrize("component", ["upstream", {"name": "upstream"}, {"name": "upstream", "version": "1", "license": None}])
def test_upstream_material_requires_name_version_and_license(component):
    with pytest.raises(ValueError):
        inventory(base_models=[component])


def test_declared_materials_and_parent_are_preserved():
    upstream = {"name": "base", "version": "2", "license": "Apache-2.0"}
    built = inventory(base_models=[upstream], dependencies=[upstream], adapters=[upstream],
                      datasets=["https://data.maintainers.dev/releases/v1"], parent_signature_sha256="ab" * 32)
    assert aibom.check(built) == []
    assert built["parent_signature_sha256"] == "ab" * 32


@pytest.mark.parametrize("field,value", [
    ("pipeline_ref", None), ("pipeline_ref", "TODO"), ("data_provenance", "unknown"),
    ("licenses", []), ("licenses", [None]), ("parent_signature_sha256", "ab"),
])
def test_inventory_rejects_missing_or_placeholder_provenance(field, value):
    with pytest.raises(ValueError):
        inventory(**{field: value})


@pytest.mark.parametrize("value", [None, [], "value", 2, False])
def test_top_level_metadata_types_return_problems(value):
    assert aibom.check(value)
    assert attestation.check(value)


@pytest.mark.parametrize("value", [None, [], "value", 2, False, {}])
def test_nested_inventory_types_return_problems(value):
    for field in ("sai_model", "data", "dependencies", "licenses"):
        document = inventory()
        document[field] = value
        if field == "dependencies" and value == []:
            continue
        assert aibom.check(document)


@pytest.mark.parametrize("value", [None, [], "value", 2, False, {}])
def test_nested_attestation_types_return_problems(value):
    for field in ("model", "tests", "tier", "catalogs", "created", "evaluator", "independent_redteam"):
        document = body()
        document[field] = value
        # A false independent flag is correct for a T1 declaration.
        if field == "independent_redteam" and value is False:
            continue
        assert attestation.check({"body": document, "signature": {}})


@pytest.mark.parametrize("tests", [None, [], [{"name": name} for name in attestation.MINIMUM_TESTS]])
def test_no_test_results_are_fabricated(tests):
    with pytest.raises(ValueError):
        body(tests=tests)


def test_not_applicable_requires_reason_and_duplicates_are_rejected():
    tests = results()
    tests[0]["result"] = "not-applicable"
    tests[0]["notes"] = ""
    tests[0]["evidence_ref"] = "eval/report.json"
    with pytest.raises(ValueError, match="reason"):
        body(tests=tests)
    tests[0]["notes"] = "This non-generative classifier does not accept textual prompts."
    assert body(tests=tests)["tests"][0]["result"] == "not-applicable"
    with pytest.raises(ValueError, match="duplicate"):
        body(tests=tests + [tests[0]])


def test_test_evidence_reference_can_replace_notes_for_performed_test():
    tests = [{"name": name, "result": "pass", "evidence_ref": f"eval/{name}.json"}
             for name in attestation.MINIMUM_TESTS]
    assert body(tests=tests)["tests"] == tests


@pytest.mark.parametrize("value", [None, "2026-10-24", "2026-10-24T12:00:00", "2026-99-24T12:00:00Z", "2026-10-24T12:00:00+02:00"])
def test_attestation_timestamp_must_be_explicit_and_utc(value):
    with pytest.raises(ValueError, match="timestamp"):
        body(created=value)


def test_t3_requires_boolean_independence_claim():
    for independent in (False, "true", 1, None):
        with pytest.raises(ValueError):
            body(tier="T3", independent=independent)
    assert body(tier="T3", independent=True)["independent_redteam"] is True


def test_tampered_attestation_is_not_accepted():
    signed = attestation.sign_body(body(), "ed25519", crypto.generate_keyfile("ed25519"))
    tampered = deepcopy(signed)
    tampered["body"]["tests"][0]["result"] = "pass"
    assert attestation.check(tampered)
    tampered = deepcopy(signed)
    tampered["signature"] = {"alg": "ed25519", "signature": []}
    assert attestation.check(tampered)


def test_legacy_metadata_does_not_silently_validate_as_v2():
    document = inventory()
    document["_type"] = "https://spdx.org/rdf/3.0.1/ai-profile"
    assert aibom.check(document)
    signed = {"body": body(), "signature": {}}
    signed["body"]["_type"] = "https://sail-gpl.org/srm/attestation/v1"
    assert attestation.check(signed)


CARD = """# Model card
## Intended use
Classifies synthetic records for release verification demonstrations.
## Out-of-scope use
Do not use this demonstration model for decisions affecting real people.
## Limitations
The artificial records do not represent operational deployment conditions.
## Security evaluation
The accompanying attestation records the supplied test methods and results.
"""


def test_model_card_requires_meaningful_risk_sections():
    assert attestation.check_model_card(CARD) == []
    for text in ("", "# card", CARD.replace("## Limitations", "## Missing"), CARD.replace("The artificial records do not represent operational deployment conditions.", "TODO")):
        assert attestation.check_model_card(text)


def test_security_document_requires_explicit_working_contact_fields():
    policy = attestation.security_md("security@maintainers.dev", "https://maintainers.dev/security")
    assert attestation.check_security_md(policy) == []
    web_contact = attestation.security_md("https://github.com/maintainers/project/security/advisories/new", "https://maintainers.dev/security")
    assert attestation.check_security_md(web_contact) == []
    for text in ("https://maintainers.dev", policy.replace("**Contact:**", "**Something:**"),
                 policy.replace("## CVD process", "## Missing"), policy + "\nContact: extra@maintainers.dev"):
        assert attestation.check_security_md(text)


@pytest.mark.parametrize("contact,policy", [
    ("security@example.org", "https://maintainers.dev/security"),
    ("security@maintainers.dev", "https://example.org/security"),
    ("not an email", "https://maintainers.dev/security"),
    ("security@maintainers.dev", "http://maintainers.dev/security"),
    ("security@maintainers.dev", "https://user:password@maintainers.dev/security"),
])
def test_placeholder_and_ambiguous_security_fields_are_rejected(contact, policy):
    with pytest.raises(ValueError):
        attestation.security_md(contact, policy)
