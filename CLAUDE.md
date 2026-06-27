# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is **not a software project** — it is the authoring home of the **SAIL‑GPL (Secure AI General Public License) v1.0 — Assured‑Integrity Edition**, a proposed copyleft license for AI model artifacts. There is no build system, no test suite, no dependencies, and (currently) no git history. Work here is editing prose, legal/spec text, and a presentation webpage.

The license is a *proposal and engineering specification, not legal advice*. Its core idea: cybersecurity, provenance, and integrity (signing, AIBOM, model card, adversarial attestation, coordinated vulnerability disclosure — collectively the **Secure‑Release Metadata / SRM**, §7) are made a copyleft condition of the grant, so they propagate to every fine‑tune and redistribution.

## Files and how they relate

- `SAIL-GPL-1.0.md` — **the canonical source of truth.** The full numbered license text (§0–§17). Any substantive change to license meaning starts here.
- `web/sail-gpl.html` — a self‑contained marketing/landing page presenting the same license (single file: inline `<style>` in `:root` CSS variables + inline content; no external assets or build step). It paraphrases and restructures the markdown for the web; it is **not** a generated render of the `.md`. It links up one level to `../SAIL-GPL-1.0.md`. The committed `web/sail-gpl-fullpage.png` is a headless‑Chrome render of this page — regenerate it when the page changes. Per earlier direction, the visible page text avoids `→` arrows, prose semicolons, and `+` signs.
- `sail/` — the reference `sail` toolkit (Python): builds, signs, and verifies SRM bundles. See `sail/README.md`.
- `example-model/` — a complete, signed example SRM bundle that `sail verify` reports COMPLIANT.
- `DI_strategija_2iniciatyva_kibernetinis_saugumas.docx` — a local-only Lithuanian-language strategy document. It is **gitignored and not committed** (the repo is public); do not add it.

**Critical:** `SAIL-GPL-1.0.md` and `web/sail-gpl.html` are maintained **independently** — there is no pipeline that regenerates one from the other. When you change license substance, update **both** so they stay consistent (section numbers, tier table §8, the §7.x obligations, the comparison table §13, and the `srm/` bundle layout §14.2).

## Conventions to preserve

- **Section numbering is referenced internally and externally.** Clauses cite each other by number (e.g. "§7.4", "§8 tier", "renews them (§7.8)"). Do not renumber sections without updating every cross‑reference.
- **Non‑ASCII typography is intentional.** The name is written `SAIL‑GPL` with a U+2011 non‑breaking hyphen, and the text uses curly quotes/em‑dashes throughout. The SPDX identifier, by contrast, is plain ASCII `SAIL-GPL-1.0`. Keep these distinct; don't normalize the branded hyphen to a plain `-`.
- **The license text is declared non‑modifiable** (§17, and the footer): verbatim copying is permitted, modification of the license *document* is not. Treat edits as drafting changes to an unreleased draft, not amendments to a published license — flag anything that changes legal meaning rather than silently rewording.
- **Companion specs:** OpenMDW (permissive base grant) is referenced in §2 as a layer SAIL‑GPL sits on top of. **QGPL is deliberately not referenced in the license itself** — it appears only in the web page's Ecosystem section. Keep it that way: the license stands on its own.

## Toolkit and bundle

The `sail` CLI (§14.3) and the `srm/` bundle layout (§14.2) are **implemented** here, not just specified. The toolkit is in `sail/` (src layout, `cryptography` for Ed25519/ECDSA, optional `liboqs` for ML‑DSA/hybrid) with tests in `sail/tests/`; CI (`.github/workflows/ci.yml`) runs the tests and `sail verify ./example-model` on every push. Treat §7 and §14 as the spec the code must keep matching — if you change either, change the other.
