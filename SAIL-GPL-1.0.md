# SAIL‑GPL — Secure AI General Public License

**Version 1.0 — Assured‑Integrity Edition**
**SPDX identifier:** `SAIL-GPL-1.0` *(proposed — not yet registered with SPDX)*
**Maintained under:** The Open Reality Initiative
**Status:** Draft for public review. This is a license *proposal* and engineering specification, not legal advice. Have counsel review before adopting in production.

> **"You may own the weights. You may not ship them unverifiable."**

---

## 0. Abstract

**SAIL‑GPL is a copyleft license for AI models in which cybersecurity is a condition of the grant, not an afterthought.**

Where GPL protects *source code*, OpenRAIL embeds *ethical use* restrictions, and OpenMDW/Apache‑2.0 grant *permissive freedom*, none of them require that a model be **signed, provenance‑bearing, security‑evaluated, and disclosable** before it is shipped — and none make those properties **travel with every fine‑tune and redistribution**. SAIL‑GPL closes that gap.

If you receive a model under SAIL‑GPL, you receive broad rights to use, study, modify, and redistribute it. In return, **whenever you distribute the model or a derivative, you must ship verifiable Secure‑Release Metadata** (Section 7): a cryptographic signature over a complete manifest, an AI Bill of Materials, a model card with intended‑use and risk disclosure, a minimum adversarial‑security attestation, and a coordinated‑vulnerability‑disclosure contact. Strip the security, and you lose the license.

---

## 1. Why SAIL‑GPL exists

### 1.1 Model weights are *data*, not code — and the law knows it
The Linux Foundation's **OpenMDW** ("Open Model, Data and Weights", 2025) exists precisely because model parameters are fundamentally **data**, so applying a code license (MIT/Apache/GPL) to weights is legally ambiguous around database rights, *sui generis* rights, and trade‑secret‑embodied material. SAIL‑GPL inherits OpenMDW's broad, multi‑right grant **and adds a security copyleft** on top.

### 1.2 Today's AI licenses optimize for the wrong axis
| Family | What it enforces | What it does **not** enforce |
|---|---|---|
| **Apache‑2.0 / MIT / OpenMDW** | Maximal permissive freedom | Any security, integrity, or provenance property |
| **OpenRAIL / RAIL** | *Behavioral* (ethical) use restrictions that propagate to derivatives | Technical integrity, signing, supply‑chain assurance |
| **Llama / Gemma community licenses** | Commercial gating, naming, acceptable‑use | Verifiable provenance or red‑team attestation |
| **SAIL‑GPL** | **Cybersecurity, integrity & provenance as a copyleft obligation** | (Ethics handled by an optional add‑on module, §9.3) |

RAIL proved that **copyleft‑style obligations can ride on a model and bind downstream users** — roughly 50,000 models on Hugging Face already carry RAIL terms. SAIL‑GPL applies that same propagation mechanism to **security** instead of ethics.

### 1.3 The supply chain is now the attack surface
2025–2026 made the threat concrete: poisoned packages compromising tens of thousands of AI pipelines, malicious LoRA adapters, model‑source tampering, and the first autonomous AI‑orchestrated intrusion campaigns. Industry responded with **OpenSSF Model Signing (OMS)**, **Sigstore Model Transparency**, the **Coalition for Secure AI (CoSAI)** model‑signing and incident‑response frameworks, and **Google SAIF**. These are excellent *tools* — but they are voluntary. SAIL‑GPL makes the **good practice the licensing default**: a model released under it is unverifiable‑proof by construction.

### 1.4 Regulation is converging on exactly this
The **EU AI Act** (high‑risk obligations from 2027), the **EU Cyber Resilience Act** (vulnerability reporting from Sept 2026, full obligations Dec 2027), **NIS2**, and **ISO/IEC 42001** all push toward provenance, logging, post‑market monitoring, and coordinated vulnerability disclosure. SAIL‑GPL gives open‑model publishers a single, machine‑checkable way to **demonstrate** those properties at release time.

---

## 2. Scope & relationship to other licenses

- **SAIL‑GPL covers the Model Artifact** — weights/parameters, architecture configuration, tokenizer/processor, and accompanying inference code and metadata required to run or fine‑tune it.
- **It complements, not replaces, code licenses.** Training/inference *source code* can remain under Apache‑2.0 or GPL; the *model artifact* it produces is released under SAIL‑GPL.
- **It can be layered over OpenMDW.** OpenMDW supplies the permissive multi‑right grant; SAIL‑GPL adds the §7 security copyleft as additional conditions.

---

## 3. The Five Principles of SAIL‑GPL

1. **Verifiable Origin.** An AI model is a claim about how it was made. A model that cannot be cryptographically traced to its maker is untrusted by default — *unsigned is unsafe*.
2. **Inseparable Security.** Security obligations are entangled with the weights. You cannot remove them by fine‑tuning, quantizing, merging, or re‑hosting. *What rides the model, rides every derivative.*
3. **Independence from Infrastructure.** Owning the GPUs, the cluster, or the serving stack grants you no exemption. The duty attaches to the **artifact**, wherever it runs.
4. **Transparency of Risk.** Capability without disclosed limits is a liability. Known weaknesses, evaluation results, and intended‑use boundaries must travel with the model.
5. **Coordinated Resilience.** Integrity must outlive a single release: revisions are re‑signed, algorithms stay agile (and post‑quantum‑ready), and vulnerabilities are handled through coordinated disclosure rather than silence.

---

## 4. Definitions

- **Model Artifact ("the Model").** The trained parameters (weights and biases) together with architecture/config files, tokenizer or pre/post‑processors, and any inference code and metadata distributed to run or adapt it.
- **Weights.** The numerical parameters resulting from training or fine‑tuning, in any format (e.g., safetensors, GGUF) or precision (including quantized forms).
- **Derivative Model.** Any model produced from a SAIL‑GPL Model by fine‑tuning, LoRA/adapter application, distillation that uses the Model's outputs or internals, merging, pruning, quantization, or continued pre‑training.
- **Distribute / Convey.** To make the Model or a Derivative Model available to any third party, including via download, API weight‑transfer, container image, or embedding in a product. *(Internal use that is not conveyed to third parties does not by itself trigger §7, but see §8 deployment tiers.)*
- **Provenance.** The verifiable record of the Model's origin and transformation history.
- **Secure‑Release Metadata (SRM).** The bundle required by §7 that must accompany every distribution.
- **AI Bill of Materials (AIBOM).** A machine‑readable inventory of the Model's constituent and upstream materials (base model, datasets or a data‑provenance statement, adapters, key dependencies, training pipeline references), e.g., in SPDX 3.0 AI/CycloneDX‑ML profile.
- **Security Attestation.** A signed statement describing the adversarial/security evaluation performed on the Model and its results.
- **Steward.** The party that distributes the Model and is responsible for its SRM.
- **OMS.** The OpenSSF Model Signing specification (detached signature over a manifest hashing all model files; keyless via Sigstore or PKI/self‑signed keys).

---

## 5. Grant of rights

Subject to the conditions of this License, the Steward grants you a **worldwide, royalty‑free, non‑exclusive** license, under all **copyright, patent, database/*sui generis*, and trade‑secret rights embodied in the Model**, to:

(a) **use and run** the Model for any purpose;
(b) **study and inspect** the Model;
(c) **modify** the Model and create Derivative Models; and
(d) **reproduce and Distribute** the Model and Derivative Models,

provided that you comply with Sections 6–9. The grant explicitly includes the right to fine‑tune, quantize, and adapt. Patent rights are granted per Section 10.

---

## 6. Copyleft — "Inseparable Security" (share‑alike)

If you Distribute the Model or any Derivative Model, then:

6.1 **Same license.** You must license your distribution as a whole under **SAIL‑GPL v1.0 (or a later version, at the recipient's option)**. You may not impose further terms that remove the §7 obligations or the recipients' rights under §5.

6.2 **Security travels.** The §7 Secure‑Release Metadata obligations **apply to every Distribution of every Derivative Model**, regardless of how small the change. Fine‑tuning, merging, quantizing, or re‑hosting does **not** discharge them — it renews them (§7.8).

6.3 **No security stripping (anti‑tivoization for assurance).** You may not distribute the Model inside a system, container, or hardware that technically prevents recipients from **verifying** its provenance or from exercising their §5 rights on a Derivative Model. Access locks that defeat verification are prohibited, mirroring GPL's anti‑DRM stance applied to integrity.

---

## 7. Mandatory Secure‑Release Metadata (the core obligation)

> *Every Distribution MUST be accompanied by a complete, verifiable SRM bundle. A distribution lacking compliant SRM is a license violation (§11).*

**7.1 Signed provenance (REQUIRED).**
Every Distribution must include an **OMS‑compatible signature** over a manifest that cryptographically hashes **all** Model files (weights, config, tokenizer, inference code). Signing may use keyless Sigstore, enterprise PKI, or self‑signed keys, but the signature, manifest, and verification material must be shipped with the artifact. Where a transparency log is used, the inclusion proof should be provided.

**7.2 AI Bill of Materials (REQUIRED).**
Ship a machine‑readable **AIBOM** declaring: the base/upstream model(s) and their licenses; datasets used or a documented data‑provenance statement; applied adapters/LoRAs; material software dependencies; and a reference to the training/fine‑tuning pipeline. Use SPDX 3.0 AI profile or CycloneDX‑ML.

**7.3 Model card with intended use & risk (REQUIRED).**
Provide a model card documenting intended use, out‑of‑scope/prohibited use, known limitations and failure modes, and security‑relevant evaluation results, consistent with the **NIST AI RMF** "Map/Measure" functions.

**7.4 Adversarial‑security attestation (REQUIRED; scope scales with §8 tier).**
Provide a signed **Security Attestation** stating which adversarial tests were performed and the results, drawn from a recognized catalog — **OWASP Top 10 for LLM Applications**, **MITRE ATLAS**, and the **CoSAI Risk Map**. Minimum coverage by tier is defined in §8 and must address, at minimum: prompt‑injection / jailbreak resistance, training‑data‑extraction / memorization, and a poisoning/back‑door check appropriate to the model class.

**7.5 Integrity over time & crypto‑agility (REQUIRED).**
Signatures must declare their algorithm and remain **agile**: as standards evolve, re‑signing with current algorithms is required for continued distribution. Stewards **SHOULD** use post‑quantum or hybrid signatures (e.g., ML‑DSA per FIPS 204) for long‑lived models. *("Harvest‑now, forge‑later" applies to model signatures too.)*

**7.6 Coordinated Vulnerability Disclosure (REQUIRED).**
Publish a security contact and a CVD policy (a `SECURITY.txt`/`SECURITY.md` is sufficient). Commit to handling reports per a recognized process (e.g., the CoSAI AI incident‑response guidance). The contact and policy must propagate to Derivative Models.

**7.7 Verification must be free and unencumbered (REQUIRED).**
The format and tooling needed to verify §7 must be open and re‑implementable. You may not require recipients to use proprietary, fee‑bearing, or single‑vendor tooling to check compliance.

**7.8 Re‑attestation on derivation (REQUIRED).**
When you create and Distribute a Derivative Model you must: re‑sign (7.1), update the AIBOM to record your changes and the parent's signature (7.2), refresh the model card (7.3), and provide an attestation covering material new capabilities or risks (7.4). You inherit the parent's CVD obligations (7.6).

A reference bundle layout and the `sail` CLI (`sail sign | verify | audit`) are described in §14.

---

## 8. Deployment & capability tiers (proportionality)

Obligations scale with risk so that research is not over‑burdened and frontier deployment is not under‑secured:

| Tier | Description | §7 obligations |
|---|---|---|
| **T0 — Research / not conveyed** | Internal experiments, not distributed to third parties | None triggered (good practice encouraged). Distribution → at least T1. |
| **T1 — Open release, low capability** | Small/narrow models distributed publicly | 7.1, 7.2, 7.3, 7.6, 7.7 required; 7.4 = lightweight self‑attestation |
| **T2 — General‑purpose / widely used** | Capable general models, or any model embedded in a product serving third parties | All of §7; 7.4 must cover the full minimum test set; 7.5 hybrid‑PQ recommended |
| **T3 — Frontier / high‑risk (EU AI Act Annex III‑type uses)** | High‑capability or safety‑critical deployment | All of §7 at strongest setting; 7.4 = independent red‑team; 7.5 PQ/hybrid signatures required; transparency‑log inclusion required |

A Steward may always meet a higher tier voluntarily. Where law (e.g., the EU AI Act) imposes stricter duties, the law controls.

---

## 9. Use, ethics, and add‑on modules

9.1 **Security‑first, not ethics‑silent.** SAIL‑GPL's mandatory core is *cybersecurity and integrity*. It does not, by itself, impose behavioral‑use restrictions, to keep the security obligation clean and OSI‑debatable rather than entangling it with content policy.

9.2 **No defeating others' assurance.** You may not use the Model to forge, strip, or falsify the Secure‑Release Metadata of any SAIL‑GPL artifact, or to knowingly produce Derivative Models designed to evade §7.

9.3 **Optional RAIL‑style module.** Stewards who want behavioral‑use restrictions may attach the **`SAIL-GPL with Responsible-Use Annex`** (an OpenRAIL‑compatible clause set). The annex is opt‑in so the base license stays a pure security copyleft.

---

## 10. Patents

Each contributor grants you a non‑exclusive, worldwide, royalty‑free **patent license** to make, use, and Distribute the Model, limited to claims necessarily infringed by their contribution. **Defensive termination:** if you initiate patent litigation alleging that the Model or a Derivative Model infringes a patent, your patent licenses under this License terminate.

---

## 11. Termination & cure

11.1 Any breach — most commonly **distributing without compliant §7 SRM**, or stripping security under §6.3 — **automatically suspends** all rights granted under §5.

11.2 **Cure period.** If the violation is your first from a given Steward and you cure it within **30 days** of becoming aware (e.g., by publishing the missing SRM), your rights are reinstated.

11.3 Rights of downstream recipients who remain in compliance are not terminated by your violation.

---

## 12. Warranty disclaimer & limitation of liability

The Model is provided **"AS IS", without warranty of any kind**. A Security Attestation under §7.4 is a good‑faith description of testing performed, **not** a guarantee of security or fitness. To the maximum extent permitted by law, no contributor or Steward is liable for damages arising from use of the Model. Nothing here waives liability that cannot be waived by law.

---

## 13. Comparison at a glance

| Property | Apache‑2.0 / OpenMDW | OpenRAIL | Llama‑style | **SAIL‑GPL v1.0** |
|---|---|---|---|---|
| Primary subject | Model/weights as data | AI artifact | Model/weights | **AI Model Artifact** |
| Weights‑as‑data / database rights | Yes (OpenMDW) | Partial | Partial | **Yes** |
| Copyleft / share‑alike | No | Behavioral copyleft | No | **Yes (security copyleft)** |
| Mandatory signing & provenance | No | No | No | **Yes (OMS, §7.1)** |
| AIBOM required | No | No | No | **Yes (§7.2)** |
| Adversarial / red‑team attestation | No | No | No | **Yes, tiered (§7.4)** |
| Coordinated vuln disclosure required | No | No | No | **Yes (§7.6)** |
| Crypto‑agility / post‑quantum‑ready | No | No | No | **Required agility; PQ for T3 (§7.5)** |
| Ethical‑use restrictions | No | Yes | Acceptable‑use | **Optional annex (§9.3)** |
| Patent grant and retaliation | Yes | Varies | Limited | **Yes (§10)** |

---

## 14. How to apply

### 14.1 NOTICE block
Add to your repository, model card, and `LICENSE`:

```
AI MODEL ARTIFACT NOTICE
This Model Artifact is released under the Secure AI General Public License
(SAIL-GPL) v1.0 — Assured-Integrity Edition.

You may use, study, modify, and distribute this Model under the terms of SAIL-GPL v1.0.
Any distribution of this Model or a Derivative Model MUST ship complete
Secure-Release Metadata (Section 7): signed manifest, AIBOM, model card,
security attestation, and a coordinated-vulnerability-disclosure contact.

Secure-Release Metadata for this distribution is provided in /srm.
SPDX-License-Identifier: SAIL-GPL-1.0
Security contact: security@your-domain.example
```

### 14.2 Reference bundle layout
```
model/
├─ model.safetensors
├─ config.json
├─ tokenizer.json
├─ MODEL_CARD.md
└─ srm/
   ├─ manifest.json            # hashes of all model files (OMS)
   ├─ model.sig                # detached signature (ML-DSA / ECDSA / hybrid)
   ├─ aibom.spdx.json          # AI Bill of Materials (SPDX 3.0 AI / CycloneDX-ML)
   ├─ security-attestation.json# §7.4 adversarial test results, signed
   └─ SECURITY.md              # §7.6 CVD policy & contact
```

### 14.3 Compliance toolkit (`sail`)
A single reference CLI, re‑implementable from an open spec:
- `sail sign ./model/` → builds the OMS manifest, signs it (keyless Sigstore, PKI, or PQ/hybrid), writes `srm/`.
- `sail verify ./model/` → checks signature, manifest completeness, AIBOM presence, attestation, and CVD contact; `--pq-only` and `--strict-issuer` modes.
- `sail audit ./release/` → walks a directory tree and reports which artifacts lack compliant §7 SRM.

### 14.4 Five‑minute compliance checklist
- [ ] Signed OMS manifest over **all** files (7.1)
- [ ] AIBOM present and machine‑readable (7.2)
- [ ] Model card with intended use and limitations (7.3)
- [ ] Security attestation for your tier (7.4)
- [ ] Algorithm declared; PQ/hybrid if T2/T3 (7.5)
- [ ] `SECURITY.md` with CVD contact (7.6)
- [ ] Verification tooling is open (7.7)
- [ ] Re‑attested if this is a Derivative Model (7.8)

---

## 15. Good practices this license operationalizes

SAIL‑GPL deliberately turns the following emerging standards from *optional* into *required‑on‑release*:

- **OpenSSF Model Signing (OMS)** and **Sigstore Model Transparency** — signing & transparency logs (adopted by NVIDIA NGC, Google Kaggle).
- **Coalition for Secure AI (CoSAI)** — Risk Map, AI Model Signing, and AI Incident Response frameworks (OASIS Open).
- **Google Secure AI Framework (SAIF)** — lifecycle coverage of data poisoning, prompt injection, model‑source tampering.
- **NIST AI RMF** — Govern/Map/Measure/Manage functions for the model card & attestation.
- **OWASP Top 10 for LLM Applications** and **MITRE ATLAS** — the adversarial test catalog for §7.4.
- **SPDX 3.0 AI profile / CycloneDX‑ML / SLSA** — the AIBOM and supply‑chain provenance backbone.
- **FIPS 203/204/205 (ML‑KEM/ML‑DSA/SLH‑DSA)** — the post‑quantum signing path.
- **EU AI Act, Cyber Resilience Act, NIS2, ISO/IEC 42001** — the regulatory obligations §7 helps evidence.

---

## 16. FAQ

**Is SAIL‑GPL "open source"?** It is a copyleft license that adds *security* conditions. Like the OSI debate over OpenRAIL, the mandatory §7 conditions may place it outside the strict OSI Open Source Definition; it is best described as **"open‑weight, assured."** §7.7 keeps verification open and vendor‑neutral.

**Does it restrict who can use the model or for what?** No — the base license restricts *how you must release*, not *what you may do*. Behavioral limits are an opt‑in annex (§9.3).

**Isn't mandatory red‑teaming heavy for hobbyists?** Tiering (§8) keeps T1 releases to a lightweight self‑attestation; heavy independent red‑teaming only attaches at T3 frontier/high‑risk.

**How is this different from just signing my model?** Signing is one of seven obligations. SAIL‑GPL also requires the AIBOM, risk disclosure, adversarial attestation, CVD, crypto‑agility, and — crucially — makes all of it **copyleft**, so it survives every fine‑tune and redistribution.

**Why a new license instead of OpenRAIL?** RAIL propagates *ethics*; SAIL‑GPL propagates *security*. They are complementary and can be combined (§9.3).

---

## 17. Versioning, governance & SPDX

- **Canonical ID:** `SAIL-GPL-1.0` (proposed). Verbatim copying of this license document is permitted; modification of the license text is not (you may, of course, license your model under it).
- **"or later":** Stewards may allow recipients to use later SAIL‑GPL versions.
- **Governance:** Maintained by **The Open Reality Initiative**. A registry of SPDX submission, the `sail` toolkit spec, and a position paper are planned.
- **Not legal advice.** This is a draft specification for community and counsel review.

---

## Sources & prior art

- OpenRAIL / Responsible AI Licenses — Hugging Face, *OpenRAIL: Towards open and responsible AI licensing frameworks* — https://huggingface.co/blog/open_rail
- OpenMDW (Open Model, Data and Weights) — LF AI & Data — https://lfaidata.foundation/blog/2025/07/22/simplifying-ai-model-licensing-with-openmdw/
- OpenSSF Model Signing (OMS) specification — https://github.com/ossf/model-signing-spec
- Sigstore Model Transparency — https://github.com/sigstore/model-transparency
- Coalition for Secure AI — model signing & incident‑response frameworks (OASIS Open) — https://www.oasis-open.org/2025/11/18/coalition-for-secure-ai-releases-two-actionable-frameworks-for-ai-model-signing-and-incident-response/
- Google Secure AI Framework (SAIF) — https://safety.google/intl/en_us/safety/saif/
- OWASP Top 10 for LLM Applications — https://genai.owasp.org/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework

---

*© 2026 Dr. Šarūnas Grigaliūnas · The Open Reality Initiative · SAIL‑GPL v1.0 — Assured‑Integrity Edition. Verbatim copies permitted; modification of this license document is not.*
