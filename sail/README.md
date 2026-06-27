# `sail` — SAIL-GPL Secure-Release Metadata toolkit

Reference implementation of the compliance CLI described in **SAIL-GPL §14.3**.
It builds, signs, and verifies the Secure-Release Metadata (SRM) bundle that
§7 makes a condition of distribution.

```
sail sign   ./model/      build the OMS manifest, sign it, write srm/
sail verify ./model/      check signature, manifest, AIBOM, attestation, CVD
sail audit  ./release/    walk a tree, report artifacts missing compliant SRM
sail keygen --out k.key   generate a signing key
```

Verification is open and re-implementable by design (§7.7): canonical JSON +
SHA-256, signatures via standard primitives, no proprietary or fee-bearing
tooling required.

## Install

```bash
cd sail
pip install -e .            # core (Ed25519 / ECDSA via `cryptography`)
pip install -e '.[pq]'      # adds post-quantum ML-DSA / hybrid (liboqs)
pip install -e '.[dev]'     # adds pytest
```

Or run without installing:

```bash
PYTHONPATH=src python -m sail verify ./model/
```

## What the bundle looks like (§14.2)

```
model/
├─ model.safetensors
├─ config.json
├─ tokenizer.json
├─ MODEL_CARD.md
└─ srm/
   ├─ manifest.json             # SHA-256 of every model file (OMS-style)
   ├─ model.sig                 # detached signature over manifest.json
   ├─ aibom.spdx.json           # AI Bill of Materials (§7.2)
   ├─ security-attestation.json # signed adversarial-test results (§7.4)
   └─ SECURITY.md               # coordinated-disclosure contact (§7.6)
```

The manifest covers **every file except `manifest.json` and `model.sig`** — so
the AIBOM, attestation, model card, and SECURITY.md are all bound under the
same signature, not just the weights.

## Signing back-ends (§7.5, crypto-agile)

| `--alg`      | Type                       | Requires            |
|--------------|----------------------------|---------------------|
| `ed25519`    | classical EdDSA (default)  | `cryptography`      |
| `ecdsa-p256` | classical ECDSA / SHA-256  | `cryptography`      |
| `ml-dsa-65`  | post-quantum, FIPS 204     | `[pq]` (liboqs)     |
| `hybrid`     | ed25519 + ml-dsa-65        | `[pq]` (liboqs)     |

The chosen algorithm is always recorded in `model.sig`, so verifiers never
guess and `--pq-only` can enforce post-quantum at T2/T3 (§8).

## Examples

Sign (a generated key is written to `--key` if it does not exist):

```bash
sail sign ./model \
  --model-name my-model --model-version 1.0.0 --tier T1 \
  --contact security@example.org --key ./signing.key
```

Verify, optionally enforcing post-quantum and a known issuer:

```bash
sail verify ./model
sail verify ./model --pq-only --strict-issuer "pki:CN=Acme Models"
sail verify ./model --json        # machine-readable report
```

Audit a release tree (non-zero exit if anything is non-compliant):

```bash
sail audit ./releases
```

A fully signed example bundle lives at [`../example-model/`](../example-model);
regenerate it with the command in [`examples/`](examples).

## Tier behaviour (§8)

| Tier | `sail` enforces                                                        |
|------|-----------------------------------------------------------------------|
| T1   | signing, manifest, AIBOM, model card, CVD; attestation may self-attest |
| T2   | the full minimum adversarial test set in the attestation              |
| T3   | full set **and** `independent_redteam: true` (pair with `--pq-only`)  |

Minimum tests (§7.4): `prompt-injection`, `training-data-extraction`,
`poisoning-backdoor`.

## Tests

```bash
cd sail && PYTHONPATH=src python -m pytest -q
```

## Status

Reference implementation of a draft license. Self-signed keys prove integrity
and continuity, not real-world identity — bind identity out of band (PKI
issuer, or a transparency log at T3). Not legal advice.
