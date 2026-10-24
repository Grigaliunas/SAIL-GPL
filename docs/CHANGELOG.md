# Draft changelog

## 2026-10-24: license draft 1.0 and SRM wire version 2

These are substantive maintainer revisions to an unreleased public draft. They do not amend a previously published immutable license. The license remains version 1.0. The incompatible technical wire format is version 2.

- Adopted SAI (Super AI) and SAIBOM as project terminology, including current models and future possibilities without a capability or certification claim.
- Expanded SAIL-GPL as Secure Super AI General Public License. Replaced the proposed unregistered short identifier in licensing metadata with `LicenseRef-SAIL-GPL-1.0`.
- Defined native SAIL SRM and SAIBOM. Removed unsupported OMS, Sigstore, SPDX, CycloneDX, keyless-signing, and PKI implementation claims. External standards remain references.
- Replaced the toolkit's former compliance label with `VERIFIED`, limited to documented technical evidence checks under externally supplied trust anchors.
- Required explicit reports for all three minimum categories at every distributed tier. Signing never generates passing results. Failed results remain visible. Non-applicability requires an explanation.
- Bound evaluator signatures to `artifact_sha256`: the digest of the sorted payload-file inventory outside root `srm/`, including the model card. This rejects replay after payload changes even when name and version are unchanged.
- Required disjoint cryptographic key material across publisher, evaluator, and log roles at T3, including hybrid components. This does not independently establish organizational separation.
- Required actual PQ or hybrid publisher signing at T3 and three external trust anchors: publisher, distinct evaluator, and log. Required a signed-checkpoint inclusion receipt anchored to that log key. T2 PQ remains recommended.
- Specified strict custom canonical JSON, SHA-256, UTC timestamps, protocol versions, complete inventories, and rejection of duplicate keys and floating-point numbers. No RFC 8785 compatibility is claimed.
- Clarified that embedded keys and issuer claims are not trust anchors. Strict issuer checks require an external publisher key.
- Rejected incomplete hybrid signatures, mismatched key types and curves, noncanonical encodings and unsigned policy overrides. Private keys are created exclusively with restrictive permissions and cannot be placed inside a release.
- Rejected symlinks, special files, malformed manifests and incomplete model cards or CVD policies. Audit recognizes common model formats, continues after malformed evidence and fails when no model is discovered.
- Added regression coverage for canonicalization, trust policies, explicit reports, Merkle inclusion proofs, evaluation replay and real ML-DSA-65 and hybrid operations. Verification never downloads a native cryptographic backend.
- Made version 1.0 the default license grant. Later versions require express Steward permission.
- Preserved independent source-code and component licenses. Integrity coverage does not override upstream rights.
- Clarified distribution triggers, inference-only use, tier declarations, and limits of automated evidence verification.

### Migration

Legacy v1 envelopes, `aibom.spdx.json`, embedded-key trust, and generated default evaluations are not accepted as v2 evidence. Supply a native SAIBOM and explicit reports, establish publisher trust independently, and rebuild the signed release. T3 additionally requires all three external publisher, evaluator, and log anchors plus an inclusion receipt. The legacy CLI spelling `--aibom` remains an alias for `--saibom`; it does not imply an SPDX format.

The demonstration contains placeholder model content and disclosed evaluation limitations. Fixture keys support reproducible verification. They do not establish real-world publisher or evaluator identities.
