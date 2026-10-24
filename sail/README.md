# sail: SAIL-GPL release evidence toolkit

The Python reference toolkit builds and checks custom SAIL Secure Release Metadata (SRM) v2 for SAI model releases. SAI means Super AI in this project. The term includes current models and does not certify superhuman capability.

`VERIFIED` means the documented technical evidence checks passed under the supplied policy. It does not establish legal compliance, model safety, or the truth of evaluation claims. At T1/T2, verification without an external publisher key is integrity-only and reports `identity_verified: false`. T3 requires externally trusted publisher, evaluator, and log keys. Production verification should pin trusted keys obtained independently of the bundle.

## Install

```bash
cd sail
python -m pip install -e .
python -m pip install -e '.[dev]'
```

Ed25519 and ECDSA P-256 use `cryptography`. Optional ML-DSA-65 and hybrid signing require `python -m pip install -e '.[pq]'` plus a compatible native liboqs runtime with ML-DSA-65 enabled. The Python extra alone does not guarantee that runtime is available. For a nonstandard native install prefix, set `OQS_INSTALL_PATH` before running the toolkit. Unsupported PQ verification fails closed; verification does not download or build a native runtime.

From the repository root, use `PYTHONPATH=sail/src python -m sail` instead of the installed `sail` command.

## Bundle and trust anchors

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
   └─ transparency.json          # required at T3
```

The manifest hashes every regular file except its own file, `srm/model.sig`, and `srm/transparency.json`. Evidence files and the model card are therefore covered. Symlinks, special files, malformed inventories, and recognized private signing material are rejected. Private keys and trust-anchor files must remain outside the model bundle.

Public descriptors contain the algorithm, public material, and full SHA-256 key identifier. A descriptor embedded in evidence is not an external trust anchor. The `--trusted-key`, `--trusted-evaluator-key`, and `--trusted-log-key` arguments read public descriptor JSON files obtained through separately authenticated channels. A path inside the model bundle is rejected. A supplied evaluator key is enforced at every tier, even where it is optional; T3 requires it.

## Prepare explicit inventory and evaluation reports

`--saibom` consumes a build-input JSON object. `--aibom` remains a legacy alias. Both use the native schema, not SPDX or CycloneDX. Required inputs are:

```json
{
  "base_models": [],
  "datasets": [],
  "data_provenance": "Describe the training data sources and any disclosure limitations.",
  "adapters": [],
  "dependencies": [],
  "pipeline_ref": "https://your-publisher-domain/pipelines/release-1",
  "licenses": ["LicenseRef-SAIL-GPL-1.0"]
}
```

Empty component lists explicitly declare that no material of that type applies. For each base model, adapter, and dependency, use an object containing nonempty `name`, `version`, and `license`. Dataset entries are string references. Data provenance is required even when dataset references are supplied. Replace all illustrative wording with actual release disclosures.

`--attestation` requires an explicit JSON object containing `tests`, optionally `evaluator` and `independent`. All tiers require these three test names:

- `prompt-injection`
- `training-data-extraction`
- `poisoning-backdoor`

Each entry requires `result` equal to `pass`, `fail`, or `not-applicable`. Supply meaningful `notes` of at least 12 characters or an `evidence_ref` of at least four characters. Non-applicability always requires explanatory notes. Optional `severity` is `info`, `low`, `medium`, `high`, or `critical`. Duplicate test names and missing categories fail validation.

The toolkit performs no model evaluation. It never fills in passing results. Failed results are retained as evidence and can produce a technically verified bundle. A verified failure report is not a safety approval. See [the demonstration inputs](examples/) for a limited-scope example.

Provide `MODEL_CARD.md` with meaningful sections titled `Intended use`, `Out-of-scope use`, `Limitations`, and `Security evaluation`. Put the tier rationale and unresolved risks in that card.

## Sign and verify

Create a publisher key outside the model:

```bash
sail keygen --alg ed25519 \
  --out publisher.key --public-out publisher.public.json

sail sign ./model \
  --model-name my-model --model-version 1.0.0 --tier T1 \
  --alg ed25519 --key publisher.key --issuer my-publisher \
  --saibom saibom-input.json --attestation test-reports.json \
  --contact https://your-publisher-domain/security/report \
  --policy-url https://your-publisher-domain/security/policy \
  --trusted-key publisher.public.json

sail verify ./model --trusted-key publisher.public.json \
  --strict-issuer my-publisher --json
```

Replace the illustrative domain with your actual reporting channel. You may instead maintain an existing `srm/SECURITY.md` with explicit `Contact:` and HTTPS `Policy:` fields plus a substantive `CVD process` section. Contact accepts an email, `mailto:` address, or HTTPS URL. Reserved demonstration domains are rejected. The verifier checks declared content, not network reachability or actual incident handling.

New private keys are created without overwriting existing files, using mode 0600 on POSIX systems. Existing permissively readable keys are rejected. Omit `--date` to record the current UTC release time. Explicit dates must be valid UTC timestamps. The timestamp is a signed publisher claim, not independent proof of time.

`--strict-issuer` requires a trusted publisher key and compares the issuer claim bound by the manifest signature. It does not perform PKI certificate or Sigstore identity validation.

For a derivative, also pass `--parent-signature-sha256` with the SHA-256 digest of the parent's `srm/model.sig` bytes. Refresh the inventory, model card, and reports. The parent reference is checked for agreement between native SAIBOM and manifest; it does not prove the truth of the claimed lineage.

## Tiers and post-quantum verification

| Tier | Technical requirements |
|---|---|
| T1 | Complete signed inventory, native SAIBOM, model card, explicit reports for all three categories, and CVD policy. Publisher self-attestation is permitted. |
| T2 | The same required evidence with evaluation scope appropriate to actual capability. PQ or hybrid signing is recommended. |
| T3 | Actual ML-DSA-65 or hybrid release signature, externally trusted publisher key, `independent_redteam: true`, a distinct externally trusted evaluator signing key, and an inclusion receipt checked against an externally trusted log key. All three roles require disjoint key material, including hybrid components. |

Algorithms are exactly `ed25519`, `ecdsa-p256`, `ml-dsa-65`, or `hybrid`. A hybrid contains exactly one Ed25519 and one ML-DSA-65 signature, in that order, and both must verify. `--pq-only` enforces actual PQ or hybrid signing at T1 or T2. It is automatic at T3.

For T3, supply all three external trust anchors and an independently signed native v2 attestation via `--attestation`. Alternatively, `--attestation-key` can sign supplied reports under a separate evaluator key using the selected `--alg`. The evaluator-signed `artifact_sha256` binds every regular file outside the root `srm/` directory, including `MODEL_CARD.md`. Reusing the same model name and version cannot make an old evaluation valid for changed payload bytes. Publisher, evaluator, and log roles must not share any cryptographic key material, including hybrid components. Distinct keys do not themselves prove organizational independence. Establish that independence and the evaluator key through a separate assurance process.

A T3 signing operation writes a pending package and returns 1 while required transparency evidence is missing. Obtain a native receipt from the log operator and attach it:

```bash
sail attach-log ./model --proof receipt.json \
  --trusted-log-key log.public.json

sail verify ./model \
  --trusted-key publisher.public.json \
  --trusted-evaluator-key evaluator.public.json \
  --trusted-log-key log.public.json
```

The receipt proves inclusion in a checkpoint signed by the pinned log key. The toolkit is not a log service and does not prove public availability, append-only consistency, freshness policy, or absence of split views. These require operational governance outside the offline checker. See [the native format specification](../docs/SRM-FORMAT.md).

## Audit and exit status

```bash
sail audit ./releases --trusted-key publisher.public.json --json
```

Audit discovers candidate model directories and applies the same verification policy. A single trust configuration applies to that invocation. Audit returns a nonzero result if no artifacts are found or any discovered artifact is not verified. Discovery covers common filenames and extensions; it does not establish that every possible artifact format was discovered.

Commands return 0 when their requested operation and required checks succeed, 1 for an incomplete or failed verification, and 2 for command or input errors. Human output states the signer-trust status and scope. JSON reports use `verified`, `identity_verified`, `scope`, and individual `checks`.

## Formats and limitations

Native SAIL SRM v2 and SAIBOM use custom strict JSON and SHA-256. Numbers are integers only. Duplicate keys, floats, invalid Unicode, and noncanonical base64 are rejected. This is not RFC 8785 canonicalization and does not claim OMS, Sigstore, SPDX, CycloneDX, keyless, or PKI interoperability.

Legacy v1 bundles must be rebuilt with explicit inputs. See [the changelog](../docs/CHANGELOG.md). The model-oriented draft license does not override independent component licenses, and a verification result is not a legal licensing opinion.

## Tests

```bash
cd sail
PYTHONPATH=src python -m pytest -q
```

The demonstration is in [example-model](../example-model/), with [regeneration instructions](examples/README.md). PQ backend execution depends on a working liboqs runtime; a passing classical test suite does not itself verify that optional runtime.
