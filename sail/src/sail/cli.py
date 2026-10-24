"""SAIL-GPL technical evidence tools for Super AI model releases."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, crypto
from .canonical import cjson, load_json
from .commands import SCOPE, Report, _write, attach_log, audit, sign, verify


def _print_report(rep: Report) -> None:
    print(f"{rep.target}  {'VERIFIED' if rep.ok else 'NOT VERIFIED'}")
    print(f"  Signer identity: {'trusted key matched' if rep.identity_verified else 'not externally authenticated'}")
    for name, ok, detail in rep.checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    print(f"  Scope: {SCOPE}")


def _report_to_dict(rep: Report) -> dict:
    return {"target": str(rep.target), "verified": rep.ok,
            "identity_verified": rep.identity_verified, "scope": SCOPE,
            "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in rep.checks]}


def _read_json(path):
    return load_json(Path(path).read_bytes()) if path else None


def _verify_options(args):
    return {"pq_only": getattr(args, "pq_only", False),
            "strict_issuer": getattr(args, "strict_issuer", None),
            "trusted_key": getattr(args, "trusted_key", None),
            "trusted_evaluator_key": getattr(args, "trusted_evaluator_key", None),
            "trusted_log_key": getattr(args, "trusted_log_key", None)}


def cmd_sign(args) -> int:
    model_dir = Path(args.path)
    spec = _read_json(args.attestation)
    document = spec if isinstance(spec, dict) and "body" in spec else None
    if document is None and not isinstance(spec, dict):
        raise ValueError("--attestation must contain explicit test reports in a JSON object")
    env = sign(model_dir, model_name=args.model_name or model_dir.resolve().name,
               model_version=args.model_version, tier=args.tier, alg=args.alg,
               key_path=Path(args.key) if args.key else None, issuer=args.issuer,
               contact=args.contact, policy_url=args.policy_url, created=args.date,
               evaluator=spec.get("evaluator", args.evaluator),
               aibom_overrides=_read_json(args.saibom),
               attestation_tests=spec.get("tests") if document is None else None,
               independent=spec.get("independent", args.independent),
               attestation_key_path=Path(args.attestation_key) if args.attestation_key else None,
               attestation_document=document,
               parent_signature_sha256=args.parent_signature_sha256)
    print(f"signed {model_dir} using {env['_signing']['alg']}")
    print(f"  key_id   {env['_signing']['key_id']}")
    print(f"  manifest {env['manifest_sha256']}")
    if not env["_key_persisted"]:
        print("  Ephemeral signing key was not saved. Use --key for continuity.", file=sys.stderr)
    rep = verify(model_dir, **_verify_options(args))
    _print_report(rep)
    if not rep.ok and args.tier == "T3":
        print("T3 remains incomplete until its signed inclusion receipt is attached and external evaluator/log keys are supplied.", file=sys.stderr)
    return 0 if rep.ok else 1


def cmd_verify(args) -> int:
    rep = verify(Path(args.path), **_verify_options(args))
    if args.json:
        print(json.dumps(_report_to_dict(rep), indent=2))
    else:
        _print_report(rep)
    return 0 if rep.ok else 1


def cmd_audit(args) -> int:
    reports = audit(Path(args.path), **_verify_options(args))
    if args.json:
        print(json.dumps([_report_to_dict(r) for r in reports], indent=2))
    else:
        for rep in reports:
            _print_report(rep)
        print(f"{len(reports)} model artifact directory(s), {sum(not r.ok for r in reports)} not verified")
        if not reports:
            print("No model artifacts discovered. Audit did not verify a release.")
    return 0 if reports and all(r.ok for r in reports) else 1


def cmd_keygen(args) -> int:
    keyfile = crypto.generate_keyfile(args.alg)
    out = Path(args.out)
    if args.public_out and Path(args.public_out).resolve() == out.resolve():
        raise ValueError("private and public key destinations must differ")
    crypto.write_private_key(out, keyfile)
    if args.public_out:
        _write(Path(args.public_out), cjson(crypto.public_descriptor(args.alg, keyfile)))
    print(f"wrote {args.alg} private key to {out}; keep it outside release bundles")
    return 0


def cmd_attach_log(args) -> int:
    attach_log(Path(args.path), _read_json(args.proof), trusted_log_key=args.trusted_log_key)
    print(f"attached verified inclusion receipt to {args.path}")
    return 0


def _trust_options(parser, *, full=True):
    parser.add_argument("--trusted-key", help="externally obtained public descriptor JSON")
    parser.add_argument("--trusted-evaluator-key", help="independent evaluator public descriptor JSON (required for T3)")
    parser.add_argument("--trusted-log-key", help="log public descriptor JSON (required for any receipt)")
    if full:
        parser.add_argument("--pq-only", action="store_true", help="require verified ML-DSA-65 or hybrid signing")
        parser.add_argument("--strict-issuer", help="require signed issuer and an externally trusted signer key")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sail", description=__doc__)
    parser.add_argument("--version", action="version", version=f"sail {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    signing = sub.add_parser("sign", help="build a native SAIL SRM v2 bundle from explicit reports")
    signing.add_argument("path")
    signing.add_argument("--model-name")
    signing.add_argument("--model-version", default="1.0.0")
    signing.add_argument("--tier", choices=["T1", "T2", "T3"], default="T1")
    signing.add_argument("--alg", choices=list(crypto.CLASSICAL) + list(crypto.PQ) + ["hybrid"], default=crypto.DEFAULT_ALG)
    signing.add_argument("--key", help="private key outside the bundle, securely created if absent")
    signing.add_argument("--issuer")
    signing.add_argument("--contact")
    signing.add_argument("--policy-url")
    signing.add_argument("--date", help="UTC ISO timestamp, defaults to the current UTC time")
    signing.add_argument("--evaluator", default="self-attestation")
    signing.add_argument("--independent", action="store_true")
    signing.add_argument("--attestation-key", help="distinct evaluator private key outside the model")
    signing.add_argument("--saibom", "--aibom", dest="saibom", required=True, help="explicit SAIBOM build inputs JSON")
    signing.add_argument("--attestation", required=True, help="explicit tests JSON or independently signed v2 attestation")
    signing.add_argument("--parent-signature-sha256", help="SHA-256 of the parent model.sig for a derivative")
    _trust_options(signing, full=False)
    signing.set_defaults(func=cmd_sign)
    verification = sub.add_parser("verify", help="check integrity and required technical evidence")
    verification.add_argument("path")
    verification.add_argument("--json", action="store_true")
    _trust_options(verification)
    verification.set_defaults(func=cmd_verify)
    auditing = sub.add_parser("audit", help="verify discovered model artifact directories")
    auditing.add_argument("path")
    auditing.add_argument("--json", action="store_true")
    _trust_options(auditing)
    auditing.set_defaults(func=cmd_audit)
    keygen = sub.add_parser("keygen", help="generate a private signing key without overwriting files")
    keygen.add_argument("--alg", choices=list(crypto.CLASSICAL) + list(crypto.PQ) + ["hybrid"], default=crypto.DEFAULT_ALG)
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--public-out", help="write public descriptor for separate, trusted distribution")
    keygen.set_defaults(func=cmd_keygen)
    log = sub.add_parser("attach-log", help="verify and attach a native signed inclusion receipt")
    log.add_argument("path")
    log.add_argument("--proof", required=True)
    log.add_argument("--trusted-log-key", required=True)
    log.set_defaults(func=cmd_attach_log)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        print(f"sail: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
