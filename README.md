# SAIL-GPL: Secure Super AI General Public License

[![CI](https://github.com/Grigaliunas/SAIL-GPL/actions/workflows/ci.yml/badge.svg)](https://github.com/Grigaliunas/SAIL-GPL/actions/workflows/ci.yml)

**Version 1.0, public draft. Custom reference: `LicenseRef-SAIL-GPL-1.0`.**

SAIL-GPL proposes continuing release evidence for SAI model artifacts: signed provenance, a Super AI Bill of Materials (SAIBOM), a model card, explicit security test reports, and coordinated vulnerability disclosure. Its Python toolkit implements the custom SAIL Secure Release Metadata (SRM) v2 format.

**SAI (Super AI)** is the project's terminology for covered model artifacts, including present models and possible future capabilities. It does not establish that superintelligence exists or certify a capability. [Iternal's terminology discussion](https://iternal.ai/super-intelligence) is inspiration, not an adopted technical classification.

This is a license proposal for community and legal review, not legal advice, an approved license standard, or security certification. `VERIFIED` means the documented technical evidence checks succeeded under the supplied trust policy. It does not certify legal compliance or absence of vulnerabilities.

| File | Purpose |
|---|---|
| [SAIL-GPL-1.0.md](SAIL-GPL-1.0.md) | Canonical draft conditions, Sections 0 through 17. |
| [sail/](sail) | Reference signing, verification, and audit toolkit. |
| [docs/SRM-FORMAT.md](docs/SRM-FORMAT.md) | Native v2 formats and verification boundaries. |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Substantive draft changes and migration notes. |
| [example-model/](example-model) | Demonstration release with explicit evaluation limitations. |
| [web/index.html](web/index.html) | Independently maintained presentation page. |

Release evidence follows derivatives. Supporting source code retains its own applicable license. A manifest records integrity without overriding upstream rights. The default model license version is 1.0 only. A later-version option requires express Steward permission.

All distributed tiers require reports addressing prompt injection, training-data extraction, and poisoning/backdoor checks. Each states `pass`, `fail`, or `not-applicable` with notes or evidence. Signing never generates passing results. T2 PQ or hybrid signing is recommended. T3 requires actual PQ or hybrid signing and three external trust anchors: the publisher key, a distinct evaluator key, and the log key used to verify an inclusion receipt. Those roles cannot share key material, including hybrid components. Evaluator signatures bind the actual model payload and card through `artifact_sha256`.

From the repository root:

```bash
PYTHONPATH=sail/src python -m sail verify ./example-model \
  --trusted-key sail/examples/example-public-key.json
```

The fixture key is a demonstration trust anchor, not independent evidence of a real publisher identity. Obtain production anchors through a separately authenticated channel. See [the toolkit guide](sail/README.md) for signing and T3 requirements.

SAIL SRM v2 and native SAIBOM are custom formats. They do not claim OMS, Sigstore, SPDX, CycloneDX, keyless-signing, or PKI interoperability. The license uses a `LicenseRef-` identifier because no SPDX listing is claimed.

Website: [sail-gpl.org](https://sail-gpl.org/). Vercel hosts the static presentation site. This GitHub repository remains the source for the site, license and toolkit. The canonical draft takes precedence over independently maintained explanatory material.

See [hosting and DNS instructions](docs/HOSTING.md) for the Vercel project, Interneto vizija records and manual deployment procedure.

Copyright 2026 Dr. Šarūnas Grigaliūnas, The Open Reality Initiative.
