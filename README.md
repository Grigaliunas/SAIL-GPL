# SAIL‑GPL — Secure AI General Public License

**Version 1.0 — Assured‑Integrity Edition** · SPDX: `SAIL-GPL-1.0` *(proposed)* · Maintained under The Open Reality Initiative

> **"You may own the weights. You may not ship them unverifiable."**

SAIL‑GPL is a **copyleft license for AI model artifacts in which cybersecurity is a condition of the grant, not an afterthought.** You receive broad rights to use, study, modify, and redistribute a model — but whenever you distribute it or a derivative, you must ship verifiable **Secure‑Release Metadata**: a signed manifest, an AI Bill of Materials, a model card with risk disclosure, an adversarial‑security attestation, and a coordinated‑vulnerability‑disclosure contact. Strip the security, and you lose the license.

It is a **license proposal and engineering specification, not legal advice.** Have counsel review before adopting in production.

## Contents

| File | What it is |
|---|---|
| [`SAIL-GPL-1.0.md`](SAIL-GPL-1.0.md) | The canonical license text (§0–§17) — the source of truth. |
| [`sail-gpl.html`](sail-gpl.html) | A self‑contained landing page presenting the license. |
| [`sail-gpl-fullpage.png`](sail-gpl-fullpage.png) | Full‑page render of the landing page. |
| [`CLAUDE.md`](CLAUDE.md) | Guidance for working in this repository. |

## What it requires (Section 7)

Every distribution must ship a complete, verifiable Secure‑Release Metadata bundle:

- **§7.1 Signed provenance** — an OpenSSF Model Signing (OMS) signature over a manifest hashing all model files.
- **§7.2 AI Bill of Materials** — base model, datasets or data‑provenance, adapters, dependencies, pipeline.
- **§7.3 Model card and risk** — intended use, out‑of‑scope use, failure modes, security evals.
- **§7.4 Adversarial attestation** — signed results vs. OWASP LLM Top 10, MITRE ATLAS, CoSAI Risk Map.
- **§7.5 Crypto‑agility** — declared algorithms, re‑signing on revision, post‑quantum / hybrid for long‑lived models.
- **§7.6 Coordinated disclosure** — a published security contact and CVD policy that propagates to derivatives.
- **§7.7 Open verification** — verification tooling must be open and re‑implementable.
- **§7.8 Re‑attest on derivation** — fine‑tune, merge, or quantize renews the obligations, never discharges them.

Obligations scale with capability tier (T0 research through T3 frontier / high‑risk).

## Preview

![SAIL‑GPL landing page](sail-gpl-fullpage.png)

## Status

Draft for public review. Not yet OSI/SPDX‑registered. Verbatim copying of the license document is permitted; modification of the license text is not — you may, of course, license your model under it.

© 2026 Dr. Šarūnas Grigaliūnas · The Open Reality Initiative
