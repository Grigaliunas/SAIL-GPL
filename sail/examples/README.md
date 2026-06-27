# Example bundle

[`../../example-model/`](../../example-model) is a complete, signed SRM bundle.
Regenerate it from the repository root with:

```bash
PYTHONPATH=sail/src python -m sail sign ./example-model \
  --model-name sail-example --model-version 1.0.0 --tier T1 \
  --alg ed25519 --key ./signing.key \
  --issuer "self-signed:the-open-reality-initiative" \
  --contact "security@open-reality.example" \
  --policy-url "https://open-reality.example/security" \
  --aibom sail/examples/example-aibom.json \
  --date "2026-06-27T00:00:00Z"
```

`example-aibom.json` holds the §7.2 inputs (it is a build input, not part of the
shipped bundle). The private key is written to `./signing.key`; it is gitignored
and not committed — the public key needed to verify is embedded in
`example-model/srm/model.sig`.

Verify the result:

```bash
PYTHONPATH=sail/src python -m sail verify ./example-model
```
