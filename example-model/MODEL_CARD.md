# Model Card — SAIL Example Model v1.0.0

A tiny, non-functional example model used to demonstrate a complete SAIL-GPL
Secure-Release Metadata (SRM) bundle. It produces no useful output and exists
only so the `sail` toolkit has something real to sign, hash, and verify.

## Intended use (§7.3)

- **In scope:** demonstrating SRM structure, signing, and verification.
- **Out of scope / prohibited:** any production inference. The weights are empty.

## Known limitations and failure modes

- The model has no trained parameters and cannot perform any task.
- Tokenizer covers a toy vocabulary only.

## Security-relevant evaluation

See `srm/security-attestation.json` for the signed adversarial-security
attestation (§7.4): prompt-injection, training-data-extraction, and
poisoning/back-door checks, at tier T1 self-attestation.

## License

Released under SAIL-GPL v1.0. Distribution requires complete SRM (§7).
Security contact: see `srm/SECURITY.md`.
