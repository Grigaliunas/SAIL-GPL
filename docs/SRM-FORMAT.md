# Native SAIL Secure Release Metadata v2

This document specifies the reference toolkit's custom wire format for SAI model release evidence. SAI means Super AI in this project and does not certify superhuman capability. License version 1.0 and wire format version 2 are separate. No OMS, Sigstore, SPDX, CycloneDX, or RFC 8785 serialization compatibility is claimed.

## 1. Encoding and primitives

JSON is UTF-8 without a byte-order mark. Canonical encoding has sorted object keys, compact comma and colon separators, no added whitespace, and no trailing newline. Keys sort by Unicode code point. Unicode text is preserved without normalization. Strings use standard JSON escaping with non-ASCII characters emitted as UTF-8.

Supported values are objects with string keys, arrays, strings, integers, booleans, and null. Every floating-point value, including finite decimals and exponent forms, is rejected. Duplicate keys, NaN, Infinity, malformed UTF-8, and unpaired surrogates are rejected. Booleans are not valid substitutes for integer schema fields.

SHA-256 digests are 64 lowercase hexadecimal characters. Base64 uses the standard alphabet and canonical padding, without whitespace or noncanonical padding bits. UTC timestamps identify a calendar date and time with `Z` or `+00:00`, optionally fractional seconds. Their truth and freshness require a separate policy.

## 2. Public descriptors and signatures

Single-algorithm public descriptors have exactly these fields:

```json
{
  "alg": "ed25519",
  "public_key": "<canonical base64 public bytes>",
  "key_id": "<full lowercase SHA-256 of public bytes>"
}
```

For `ed25519` and `ecdsa-p256`, public bytes are canonical DER SubjectPublicKeyInfo and must match the declared key type and curve. For `ml-dsa-65`, they are raw ML-DSA-65 public bytes. A signature object adds `signature`, containing canonical base64 signature bytes.

Ed25519 signs the supplied payload bytes directly. ECDSA uses P-256 with SHA-256 and the library's DER-encoded ECDSA signature. ML-DSA-65 uses the optional liboqs backend. Unsupported algorithms fail closed.

A hybrid descriptor has exactly `alg: "hybrid"`, `signatures`, and `key_id`. Its `signatures` array contains exactly an Ed25519 public descriptor followed by an ML-DSA-65 descriptor. Its key identifier is SHA-256 of the concatenated raw public-material bytes in that order. A hybrid signature uses the same shape with both complete component signature objects. Both components sign the same payload and both must verify. Empty, repeated, swapped, or partial components are invalid.

A trust anchor is a public descriptor obtained independently. The CLI rejects trust-anchor paths inside the model directory. Matching a bundle-provided issuer string alone does not authenticate identity.

## 3. Complete manifest

`srm/manifest.json` is canonical JSON with:

| Field | Value |
|---|---|
| `_type` | `https://sail-gpl.org/srm/manifest/v2` |
| `schema_version` | String `"2"` |
| `model` | Object with nonempty `name` and `version` |
| `created` | UTC release timestamp |
| `tier` | `T1`, `T2`, or `T3` |
| `signing` | Actual `alg`, full `key_id`, and nonempty `issuer` claim |
| `hash_algorithms` | Exactly `["sha256"]` |
| `files` | Array of `path`, integer `size`, and `sha256` entries |
| `file_count` | Integer number of entries |
| `total_bytes` | Integer sum of declared file sizes |
| `files_digest` | SHA-256 of canonical JSON encoding of `files` |
| `derived_from` | Optional object with `parent_signature_sha256` |

The inventory covers every regular file below the model directory except:

- `srm/manifest.json`
- `srm/model.sig`
- `srm/transparency.json`

All other evidence files and the model card are included. File entries use unique relative POSIX paths without empty components, backslashes, absolute paths, `.`, or `..`. The builder sorts entries by path. Verifiers check missing and additional files, actual sizes, digests, summary values, and the file-list digest. The tree rejects symlinks and special files. Common private-key encodings and `.key` files are rejected as accidental secret publication checks, not a general secret scanner.

`parent_signature_sha256` is the SHA-256 digest of the parent release's `srm/model.sig` bytes. It must agree with the SAIBOM's parent reference. This records a lineage claim but does not validate the parent artifact or independently establish derivation.

## 4. Release envelope

`srm/model.sig` contains:

```json
{
  "_type": "https://sail-gpl.org/srm/signature/v2",
  "schema_version": "2",
  "manifest_sha256": "<SHA-256 of exact canonical manifest bytes>",
  "signature": {
    "alg": "ed25519",
    "public_key": "<canonical base64 public bytes>",
    "key_id": "<full lowercase SHA-256 of public bytes>",
    "signature": "<canonical base64 signature bytes>"
  }
}
```

The signature object signs the entire canonical manifest bytes. The verifier checks the digest, canonical manifest encoding, actual signature, and agreement of the manifest's signed algorithm and key identifier with the verified signature. Issuer, tier, model identity, and release time are bound through the signed manifest.

The envelope's identifying fields are validated protocol labels, not independently signed assertions. The security-relevant identity and policy claims are inside the signed manifest.

## 5. Native SAIBOM

`srm/saibom.json` is a custom document, not an SPDX or CycloneDX document:

| Field | Value |
|---|---|
| `_type` | `https://sail-gpl.org/srm/saibom/v2` |
| `schema_version` | String `"2"` |
| `name` | Model name, hyphen, model version |
| `sai_model` | `name`, `version`, explicit `baseModels` and `adapters` arrays |
| `data` | Explicit `datasets` array and meaningful `provenanceStatement` |
| `dependencies` | Explicit component array |
| `pipeline` | Nonempty training or adaptation pipeline reference |
| `licenses` | Nonempty array of license identifiers or custom references |
| `parent_signature_sha256` | Optional parent signature digest |

Base-model, adapter, and dependency entries are objects with nonempty `name`, `version`, and `license`. Empty arrays explicitly state that no component applies. Dataset entries are string references. Provenance text must be meaningful and at least 12 characters. Pipeline text must contain at least four characters. Obvious template values are rejected, but validation cannot prove disclosure completeness or accuracy.

Model name and version must match the signed manifest. The model license reference used by this project is `LicenseRef-SAIL-GPL-1.0`. Each independently licensed component retains its own actual license identifier.

The CLI consumes a build-input object using `base_models`, `datasets`, `data_provenance`, `adapters`, `dependencies`, `pipeline_ref`, and optionally `licenses`. It derives the final document identity from command arguments. `--saibom` is preferred; `--aibom` is a legacy spelling for the same input.

## 6. Security attestation

`srm/security-attestation.json` has `body`, `body_sha256`, and `signature`. The digest and signature cover canonical JSON encoding of `body`. The manifest additionally hashes the complete attestation file.

The body contains:

- `_type: "https://sail-gpl.org/srm/attestation/v2"`
- `schema_version: "2"`
- `model` with `name` and `version` matching the manifest
- `tier` matching the manifest
- `artifact_sha256`, the payload inventory digest defined below
- nonempty `evaluator`
- boolean `independent_redteam`
- nonempty string-reference array `catalogs`
- valid UTC `created`
- explicit `tests` array

Each test has a unique nonempty `name`, a `result` of `pass`, `fail`, or `not-applicable`, and notes of at least 12 meaningful characters or an `evidence_ref` of at least four meaningful characters. Non-applicability requires explanatory notes. Optional `severity` is `info`, `low`, `medium`, `high`, or `critical`.

`artifact_sha256` is SHA-256 of canonical JSON encoding of the inventory of every regular file outside the root `srm/` directory. This includes `MODEL_CARD.md`. Each entry has `path`, integer `size`, and `sha256`; entries are sorted by relative POSIX path using Unicode code-point order. The digest is computed before writing SRM evidence, so it does not contain the attestation itself. Signing rejects an externally signed attestation for a different payload digest, and verification recomputes the digest from disk. Matching model name and version alone is insufficient.

All three minimum names are required at every distributed tier: `prompt-injection`, `training-data-extraction`, and `poisoning-backdoor`. Failure is valid disclosed evidence, not a safety approval. No evaluation is run by signing.

T3 requires an externally trusted publisher key matching `--trusted-key`, `independent_redteam: true`, and an attestation signature under a distinct key matching `--trusted-evaluator-key`. The log key is independently pinned as described in Section 8. Publisher, evaluator, and log roles must use disjoint underlying public-key material. Hybrid component keys count individually: a classical evaluator key cannot reuse the classical component of a publisher hybrid key. Log keys likewise cannot reuse publisher or evaluator components. This proves key separation and pinned-key agreement. Actual organizational independence and evaluation quality remain external assurance decisions. An evaluator can supply an already signed native document through `--attestation`; the publisher must not substitute a self-asserted independence flag for independent evidence.

## 7. Model card and CVD policy

`MODEL_CARD.md` must have meaningful sections titled `Intended use`, `Out-of-scope use`, `Limitations`, and `Security evaluation`. Each section needs at least 12 characters of substantive text. Validation rejects obvious template values; it cannot prove semantic adequacy.

`srm/SECURITY.md` must have one `Contact:` field with a non-placeholder email, `mailto:` address, or HTTPS URL, one `Policy:` field with a non-placeholder HTTPS URL, and a `CVD process` section with at least 40 meaningful characters. Duplicate contact or policy fields fail. Reserved example hosts fail. Endpoint reachability and response commitments are not network-tested.

## 8. Native transparency inclusion receipt

`srm/transparency.json` is required at T3. If present at another tier it is also verified. Its outer structure is:

```json
{
  "_type": "https://sail-gpl.org/srm/transparency/v2",
  "schema_version": "2",
  "manifest_sha256": "<SHA-256 of manifest bytes>",
  "leaf_index": 0,
  "audit_path": [],
  "checkpoint": {
    "_type": "https://sail-gpl.org/srm/checkpoint/v2",
    "log_id": "<full trusted log key identifier>",
    "tree_size": 1,
    "root_hash": "<Merkle root>",
    "issued_at": "<UTC checkpoint time>"
  },
  "signature": {
    "alg": "ed25519",
    "public_key": "<canonical base64 log public bytes>",
    "key_id": "<full log key identifier>",
    "signature": "<canonical base64 checkpoint signature bytes>"
  }
}
```

This example shows a one-leaf tree with an empty `audit_path`. Larger trees supply sibling hashes closest to the leaf first. All hash placeholders represent 64 lowercase hexadecimal characters.

Leaf data is the raw 32-byte SHA-256 digest of the exact manifest bytes. Its Merkle leaf hash is `SHA256(0x00 || leaf_data)`. Inner nodes use `SHA256(0x01 || left || right)`. The audit path and tree construction use RFC 6962's ordered inclusion-proof algorithm. The verifier rejects invalid indices, inconsistent paths, and paths longer than 64 hashes.

The complete canonical checkpoint object is signed by the log key. Its `log_id` must match the full key identifier independently supplied through `--trusted-log-key`. At T3, its underlying keys must be disjoint from publisher and evaluator key material, including hybrid components. The receipt's manifest digest and reconstructed root must match. A log URL is not a proof.

Attach with:

```bash
sail attach-log ./model --proof receipt.json --trusted-log-key log.public.json
```

The receipt is excluded from the manifest to avoid circular hashing. It authenticates a manifest digest's inclusion in a pinned log's signed checkpoint. This offline format does not implement a public log service, consistency proofs, split-view detection, freshness limits, or public availability checks. Trust in log operation and checkpoint distribution is a separate governance responsibility.

Re-signing removes a previous receipt because it belongs to the previous manifest. T3 remains pending until a new valid receipt and the required external trust anchors are available.

## 9. Verification result and migration

`VERIFIED` covers the documented checks under the selected policy. With no publisher trust anchor, T1/T2 verification is integrity-only and `identity_verified` is false. A supplied publisher key must match. An evaluator key supplied with `--trusted-evaluator-key` is also enforced at T1/T2; it is mandatory at T3. `--strict-issuer` additionally requires that key and the signed issuer claim. T3 requires actual PQ or hybrid publisher signing and all three external trust anchors: `--trusted-key`, `--trusted-evaluator-key`, and `--trusted-log-key`. Missing any of those anchors prevents T3 verification. At T1/T2, use an external publisher anchor for authenticated production verification.

Reports do not establish legal compliance, truth of training history, evaluation execution, freedom from vulnerabilities, or superhuman capability. Schema checks cannot detect every plausible false disclosure.

Legacy v1 envelopes and the old `aibom.spdx.json` inventory are not v2 evidence. Rebuild with explicit inventory and reports; do not relabel old objects as v2. See [the draft changelog](CHANGELOG.md).
