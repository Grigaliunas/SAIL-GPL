# SAIL-GPL: Secure Super AI General Public License

**Version 1.0, public draft. Assured Integrity Edition.**

**License reference:** `LicenseRef-SAIL-GPL-1.0` (custom, not an SPDX-listed identifier).

**Maintainer:** The Open Reality Initiative.

**Technical format:** SAIL Secure Release Metadata (SRM), wire version 2.

This is a proposed license and engineering specification for community and legal review. It is not an approved license standard, legal advice, a security certification, or evidence of superhuman capability. Substantive changes to this unreleased draft are recorded in [the changelog](docs/CHANGELOG.md).

> You may own the weights. You may not ship them unverifiable.

## 0. Abstract

SAIL-GPL proposes continuing release evidence as a condition of redistributing model artifacts. Recipients receive rights to use, inspect, adapt, and redistribute the Model, subject to the conditions below. Every distribution must carry signed provenance, a Super AI Bill of Materials (SAIBOM), a model card, explicit security test reports, and a coordinated vulnerability disclosure policy.

**SAI (Super AI)** is this project's terminology for the broad class of model artifacts covered by Section 4. It includes present models and possible future capabilities. The label does not establish that superintelligence exists, that a capability threshold has been reached, or that a model has been certified. [Iternal's terminology discussion](https://iternal.ai/super-intelligence) is terminology inspiration, not an adopted technical classification.

Technical verification checks the supplied evidence against a declared policy. It cannot establish that training disclosures are true, evaluations were performed competently, or all legal duties have been satisfied.

## 1. Why SAIL-GPL exists

### 1.1 Rights and evidence are different questions

A recipient needs permission to use a model and evidence about what was released. A signature binds particular bytes to a key. A useful release also explains upstream materials, intended use, known risks, and how to report vulnerabilities. The identity associated with a key requires a separate trust decision.

### 1.2 Security conditions should survive redistribution

This draft requires distributors to preserve and renew release evidence after fine-tuning, adaptation, merging, pruning, quantization, or other derivation. A small change does not remove those obligations.

### 1.3 An honest implementation boundary

The reference toolkit implements the custom SAIL SRM v2 format. OpenSSF Model Signing, Sigstore, SPDX, and CycloneDX are external reference projects. SAIL SRM v2 is not claimed to implement their formats or services. It provides local key-based signing, explicit public-key pinning, and a native transparency receipt described in Section 14.

### 1.4 Release evidence does not replace regulation

The bundle may support a wider assurance process. It does not replace applicable law, conformity assessment, ongoing monitoring, incident handling, data protection obligations, or sector-specific controls. Its verification result is not a determination of regulatory compliance.

## 2. Scope and relationship to other licenses

SAIL-GPL applies to the Model Artifact defined in Section 4 to the extent the Steward has authority to license it. It grants no rights that the Steward or Contributors do not hold.

Separately licensed training and inference source code retains its applicable terms. Including it in a release manifest records integrity and provenance. It does not relicense that code or override upstream rights. The SAIBOM must identify its license. The same-license condition in Section 6 applies to the covered Model and Derivative Model, not to independently licensed components merely distributed alongside them. A distributor must resolve incompatible rights before distribution.

An upstream permissive license, including OpenMDW, may permit a distributor to apply these conditions to a downstream model release. This draft does not alter that upstream license or claim blanket compatibility with a license family.

## 3. The five principles

1. **Verifiable release.** Bind all release files and required evidence to a declared signing key.
2. **Continuing assurance.** Renew the evidence when distributing a derivative.
3. **Independent trust.** Establish publisher, evaluator, and log trust outside the untrusted bundle.
4. **Disclosed limits.** Report evaluation scope, outcomes, limitations, and unresolved risks.
5. **Coordinated resilience.** Maintain disclosure channels and update evidence as risks and cryptographic requirements change.

## 4. Definitions

- **Model Artifact (the Model):** trained parameters, weights, architecture and configuration files, tokenizers and processors, and associated model metadata distributed to run or adapt the model. Independently licensed supporting source code remains subject to Section 2.
- **SAI:** the project terminology defined in Section 0. It is not a capability certification or a condition excluding present models.
- **Derivative Model:** a model produced from the covered Model by fine-tuning, adapter application, distillation using its outputs or internals, merging, pruning, quantization, or continued training, to the extent rights applicable to that derivation permit these conditions to attach.
- **Distribute / Convey:** make the Model or a Derivative Model available to a third party, including a download, weight transfer, container image, or product embedding. Returning inference outputs without conveying the Model does not by itself trigger these distribution conditions. Internal use without conveyance does not by itself trigger Section 7.
- **Steward:** a party distributing the Model and responsible for its release evidence.
- **Contributor:** a party authorizing a contribution under this License, only to the extent of rights held or controlled by that party.
- **Secure Release Metadata (SRM):** the evidence bundle required by Section 7, represented by SAIL SRM v2 in the reference implementation.
- **SAIBOM:** a machine-readable inventory of upstream models and licenses, datasets or documented data provenance, adapters, material dependencies, and a training or adaptation pipeline reference. Native SAIBOM v2 is a custom SAIL schema.
- **Security Attestation:** a signed statement identifying the model, tier, evaluator, attestation creation date, test coverage, results, and supporting notes or evidence references.
- **Trusted key:** a public key supplied through a channel independent of the bundle. An embedded key is verification material, not a trust anchor.
- **Verified:** the technical checks required by the selected verification policy succeeded. This does not certify legal compliance, real-world identity, model quality, absence of vulnerabilities, or superhuman capability.

## 5. Grant of rights

Subject to Sections 6 through 9, each Steward and Contributor grants a worldwide, royalty-free, non-exclusive license under copyright, database rights, and trade secret rights held or controlled by that party and embodied in its contribution to:

(a) use and run the Model for any purpose;

(b) study and inspect the Model;

(c) modify the Model and create Derivative Models; and

(d) reproduce and Distribute the Model and Derivative Models.

The grant includes fine-tuning, quantization, and adaptation. Patent rights are addressed in Section 10. No third-party rights are implied beyond the applicable upstream licenses.

## 6. Copyleft and continuing release evidence

6.1 **Same version by default.** Distribute the covered Model and Derivative Models under SAIL-GPL version 1.0. A Steward may expressly permit a later version for material it is authorized to license. Without that permission, recipients receive version 1.0 only. Independently licensed components retain their terms under Section 2.

6.2 **Evidence travels.** Every distribution of a Derivative Model must meet Section 7. Fine-tuning, merging, quantization, or re-hosting does not discharge these conditions. Record the applicable parent signature digest and material changes when distributing a derivative.

6.3 **Verification remains possible.** Do not distribute the covered Model in a system that technically prevents recipients from checking release evidence or exercising their Section 5 rights on a Derivative Model. Private signing keys need not be disclosed. Recipients must be able to verify the release and use their own keys for their derivatives.

## 7. Mandatory Secure Release Metadata

Every distribution must include the following evidence. The reference implementation's technical result covers only the checks it actually performs, as documented in Section 14.

**7.1 Signed provenance.** Provide a complete manifest hashing every distributed file in the model directory, including the model card and SRM evidence. Exclude only the manifest, its detached signature, and the transparency receipt that refers to the signed release. Symlinks and special files must not evade completeness checks. Bind the model identity, release time, issuer claim, and actual algorithm policy to the signed release. Verification against a publisher identity requires an independently obtained trusted publisher key. T3 verification requires all three external trust anchors: publisher, independent evaluator, and log. An embedded key alone proves no publisher identity.

**7.2 SAIBOM.** Provide `srm/saibom.json` using the native SAIBOM v2 schema. Explicitly declare upstream models and their versions and licenses, adapters, material dependencies, and a pipeline reference. Declare available dataset references and always provide meaningful data provenance. Empty lists must be explicit where nothing applies. A derivative must record the parent's signature SHA-256 digest. Native SAIBOM is not an SPDX or CycloneDX serialization. The custom license reference is `LicenseRef-SAIL-GPL-1.0`.

**7.3 Model card and risk.** Provide intended use, out-of-scope use, limitations and failure modes, evaluation scope and results, and known security risks. Explain unresolved failures and controls relevant to the release. File presence alone does not establish the truth or adequacy of disclosures.

**7.4 Explicit security attestation.** Supply evaluator-authored test reports. The toolkit must never invent passing results or treat signing as evaluation. Every T1, T2, and T3 attestation must address `prompt-injection`, `training-data-extraction`, and `poisoning-backdoor`. Each result must be `pass`, `fail`, or `not-applicable`, with meaningful notes or an evidence reference. A `not-applicable` result requires an explanation tied to the model and scope. Record failures honestly. A valid failure report may pass evidence verification and is not a statement that the Model is safe. Identify the Model, version, tier, evaluator, and UTC attestation creation time. The evaluator-signed body must include `artifact_sha256`, binding every regular file outside the root `srm/` directory, including `MODEL_CARD.md`, through the digest construction in Section 14. T3 requires an independent evaluator signature under an externally trusted key. At T3, publisher, evaluator, and log roles must use distinct cryptographic key material, including all hybrid components.

**7.5 Integrity over time and cryptographic agility.** Declare and verify the actual signing algorithm. Continue distribution only with evidence meeting the declared current release policy. PQ or hybrid signatures are recommended for long-lived models and T2 releases. T3 requires an actual ML-DSA signature or a verified hybrid containing both classical and ML-DSA components. A policy label cannot substitute for those signatures. Use UTC timestamps. A claimed timestamp is not an attestation from a trusted timestamping service.

**7.6 Coordinated vulnerability disclosure.** Include a security contact and substantive disclosure policy in `srm/SECURITY.md`. Explain how reports are handled and how affected recipients receive updates. Preserve applicable upstream disclosure obligations. The Steward is responsible for maintaining the channel. The toolkit validates syntax and declared content, not endpoint reachability or operational response.

**7.7 Open verification.** Publish formats and sufficient instructions for independent verification. Do not require proprietary or fee-bearing tools as the sole means of verifying the evidence. Trust decisions require independently established public keys.

**7.8 Re-attestation on derivation.** Re-sign each distributed derivative, update its SAIBOM and parent signature reference, refresh the model card, and provide explicit reports covering the minimum set and material new risks. Preserve the applicable disclosure policy. A publisher signature does not replace T3 independent evaluator signing.

## 8. Deployment and capability tiers

These tiers determine evidence requirements for distributions. A local or inference-only deployment does not become a distribution solely because its risk resembles a higher tier. Law may impose separate deployment duties.

| Tier | Distribution description | Release evidence |
|---|---|---|
| **T0: internal, not conveyed** | No Model distribution to third parties | Section 7 is not triggered. Distribution requires at least T1. |
| **T1: limited capability** | Small or narrow models released to third parties | All Section 7 evidence, including explicit reports for all three categories. Publisher self-attestation is permitted. |
| **T2: general-purpose or product-embedded** | Capable general models or models conveyed as part of a product | All Section 7 evidence, with scope appropriate to capability and use. PQ or hybrid signing is recommended. |
| **T3: frontier or high risk** | High-capability, safety-critical, or similarly high-risk model distributions | All Section 7 evidence, actual PQ or hybrid publisher signing, an externally trusted publisher key, a distinct externally trusted evaluator key, and a verifiable inclusion receipt anchored to an externally trusted log key. No cryptographic key material may be shared across those three roles, including hybrid components. |

The Steward must disclose its tier and explain its classification in the model card. The toolkit validates declared evidence, not the substantive correctness of a self-selected tier. A Steward may meet a higher tier voluntarily. Where law imposes stricter duties, the law controls.

## 9. Use and optional modules

9.1 **Base scope.** The base license grants use for any purpose, subject to these conditions. It imposes release-evidence conditions rather than a general acceptable-use policy.

9.2 **No falsification.** Do not knowingly forge or falsify required release evidence for a covered artifact or knowingly distribute a derivative designed to evade Section 7.

9.3 **Optional responsible-use terms.** A Steward may propose additional responsible-use terms only within its authority and must identify them separately. Such terms are not part of this base text and require separate review and explicit agreement. They cannot remove rights granted by this base license or waive required evidence. No undefined annex is automatically incorporated.

## 10. Patents

Each Contributor grants a non-exclusive, worldwide, royalty-free patent license to make, use, and Distribute the Model, limited to claims held or controlled by that Contributor and necessarily infringed by its contribution. If you initiate patent litigation alleging that the Model or a Derivative Model infringes a patent, your patent licenses under this License terminate. No unrelated third-party patent rights are granted.

## 11. Suspension and cure

11.1 A breach, including distribution without required evidence or deliberate evidence stripping, automatically suspends the breaching party's Section 5 rights.

11.2 If this is your first violation with respect to a given Steward and you cure it within 30 days after becoming aware, your rights from that Steward are reinstated. Repeated violations require express reinstatement from the relevant rights holder.

11.3 Rights of downstream recipients who remain in compliance are not suspended by your violation.

## 12. Warranty disclaimer and limitation of liability

The Model is provided **AS IS, without warranty of any kind**. A Security Attestation describes testing and reported results. It does not guarantee security, fitness, regulatory compliance, or capability. A `VERIFIED` result has the limited technical meaning in Section 4. To the maximum extent permitted by law, no Contributor or Steward is liable for damages arising from use of the Model. Nothing waives liability that cannot be waived by law.

## 13. Comparison of the assurance layers

| Layer | What it establishes | What it does not establish |
|---|---|---|
| Publisher signature and complete manifest | Release bytes match the inventory and verify under the trusted key | Publisher claims are true or the Model is safe |
| SAIBOM and model card | Required disclosures are supplied and integrity-bound | Complete rights clearance or independently verified training history |
| Signed test reports | The indicated key signed the reported scope and outcomes | Tests were executed correctly or all threats were covered |
| T3 evaluator key separation | Publisher, evaluator, and log key material is distinct, including hybrid components, and matches external anchors | Organizational independence without separate due diligence |
| T3 transparency receipt | Release inclusion in a checkpoint signed under the trusted log key | Global log consistency, absence of split views, or a public monitoring service |
| SAIL-GPL conditions | The proposed distribution conditions in this draft | OSI approval, SPDX listing, or regulatory certification |

## 14. How to apply and verify

### 14.1 Notice block

Include this notice in the model card and license material, together with the full license text and independently licensed component notices:

```text
SAI MODEL ARTIFACT NOTICE
This Model Artifact is released under the Secure Super AI General Public
License (SAIL-GPL), version 1.0, public draft.

Distribution of the covered Model or a Derivative Model must include
the Secure Release Metadata required by Section 7.
Independent supporting components retain their applicable licenses.

Secure Release Metadata: ./srm/
SPDX-License-Identifier: LicenseRef-SAIL-GPL-1.0
Security contact: security@your-domain.example
```

### 14.2 Reference bundle layout

```text
model/
├─ model.safetensors
├─ config.json
├─ tokenizer.json
├─ MODEL_CARD.md
└─ srm/
   ├─ manifest.json
   ├─ model.sig
   ├─ saibom.json
   ├─ security-attestation.json
   ├─ SECURITY.md
   └─ transparency.json         # required for T3 verification
```

SAIL SRM v2 is custom. Its JSON uses UTF-8, sorted keys, compact separators, and integer-only numeric values. Floating-point numbers, duplicate keys, and non-finite numbers are rejected. Hashes use SHA-256. This is not a claim of RFC 8785 canonicalization. Exact rules are in [SRM-FORMAT.md](docs/SRM-FORMAT.md).

The manifest covers regular release files except `srm/manifest.json`, `srm/model.sig`, and `srm/transparency.json`. The receipt is excluded to avoid circular inclusion. It binds the signed release to a signed checkpoint. The attestation's `artifact_sha256` hashes canonical JSON encoding of the path-sorted `{path,size,sha256}` inventory of every regular file outside the root `srm/` directory, including `MODEL_CARD.md`. This prevents replaying an evaluator signature after payload changes while keeping evidence outside its own digest. Trust anchors must not be inferred from bundle content.

### 14.3 Reference toolkit

- `sail keygen --out publisher.key --public-out publisher.public.json` creates a local signing key and public descriptor. Establish trust in that descriptor independently.
- `sail sign ./model --key publisher.key --saibom saibom-input.json --attestation test-reports.json ...` requires explicit inventory and reports. `--aibom` remains a legacy alias for `--saibom`.
- `sail verify ./model --trusted-key publisher.public.json` checks evidence under an independently supplied publisher key. `--strict-issuer` requires that trusted key and compares the signed issuer claim. `--pq-only` requires an actually verified PQ or hybrid signature.
- T3 requires all three external anchors: `--trusted-key publisher.public.json --trusted-evaluator-key evaluator.public.json --trusted-log-key log.public.json`. An independence declaration, embedded publisher key, or log URL alone is insufficient.
- `sail attach-log ./model --proof receipt.json --trusted-log-key log.public.json` attaches the native receipt after signing. T3 signing produces a pending package with a nonzero result until the receipt and required verification policy can be satisfied.
- `sail audit ./release` discovers candidate artifacts and reports technical verification outcomes. Discovery is a convenience, not proof that every possible model format was found.

The reference toolkit does not implement Sigstore identity issuance, PKI certificate-chain validation, OMS bundles, SPDX documents, or CycloneDX documents. A key must be pinned even when an issuer claim resembles a certificate name. `VERIFIED` means the documented evidence checks succeeded under the supplied trust policy. It does not determine legal compliance with this License.

### 14.4 Release checklist

- [ ] All release files are covered, subject only to the documented exclusions.
- [ ] Publisher trust was established independently of the bundle.
- [ ] SAIBOM declares upstream licenses, inventory, data provenance, and pipeline.
- [ ] The model card describes use, limits, tier choice, and known risks.
- [ ] Explicit signed reports cover all three categories and retain failures.
- [ ] T2 PQ signing was considered and actual T3 PQ or hybrid signing is enforced.
- [ ] T3 has externally trusted publisher, evaluator, and log keys with disjoint cryptographic key material, including hybrid components, and a valid inclusion receipt.
- [ ] A substantive disclosure policy and contact are included.
- [ ] Derivative changes and parent signature digest are recorded.
- [ ] Independent component licenses and notices are retained.

## 15. External references and implementation boundaries

These are reference projects and official source titles, not compatibility or certification claims:

- [OpenSSF Model Signing specification](https://github.com/ossf/model-signing-spec) and [Sigstore Model Transparency](https://github.com/sigstore/model-transparency): external signing ecosystems. SAIL uses its own v2 envelope.
- [SPDX Specification 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/) and [CycloneDX](https://cyclonedx.org/): external inventory standards. Native SAIBOM is separate.
- [OWASP Top 10 for Large Language Model Applications](https://genai.owasp.org/) and [MITRE ATLAS](https://atlas.mitre.org/): threat and evaluation references. Naming a category is not proof of full catalog coverage.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework): an external risk-management reference.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): the ML-DSA signature standard used by the optional PQ backend.
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962): the Merkle hashing and inclusion-proof construction used by the native receipt. SAIL checkpoint and receipt formats are custom, not a Certificate Transparency service integration.
- [Iternal's Super Intelligence terminology discussion](https://iternal.ai/super-intelligence): terminology inspiration only, not evidence that SAI is an adopted industry standard.

## 16. FAQ

**Is SAIL-GPL an approved open-source license?** No approval is claimed. This is a custom public draft requiring community and legal review. Its reference is `LicenseRef-SAIL-GPL-1.0`.

**Does SAI mean this Model is superintelligent?** No. It names covered artifacts, including current models. Capability requires separate evidence.

**Does VERIFIED mean safe or legally compliant?** No. It means the documented checks succeeded under the supplied trust policy. Failed evaluations can be valid evidence and must remain visible.

**Can signing create an evaluation report?** No. Reports must be supplied explicitly. Their authors remain responsible for accuracy and scope.

**Why do T1 releases cover all three categories?** Minimum coverage is constant. A narrow model may explain why a category is not applicable. T1 permits self-attestation. T3 requires externally trusted publisher, evaluator, and log keys, distinct evaluator signing, and transparency evidence.

**Can inference code keep its upstream license?** Yes. Section 2 preserves independent terms. Integrity coverage does not transfer rights or change those licenses.

## 17. Versioning and governance

- **License version:** 1.0, public draft. **Custom reference:** `LicenseRef-SAIL-GPL-1.0`.
- **Wire format:** SAIL SRM version 2, distinct from the license version. Legacy v1 evidence is not silently accepted as v2.
- **Later versions:** version 1.0 applies unless the relevant Steward expressly grants a later-version option under Section 6.1.
- **Governance:** maintained by The Open Reality Initiative. Substantive draft changes are recorded in [the changelog](docs/CHANGELOG.md).
- **Copying this text:** verbatim copies are permitted. Modification of the published license document is not permitted. Maintainer edits to this unreleased draft do not amend an already published license.
- **Review:** no enforceability determination is made for any jurisdiction. Obtain legal review before production adoption.

Copyright 2026 Dr. Šarūnas Grigaliūnas, The Open Reality Initiative.
