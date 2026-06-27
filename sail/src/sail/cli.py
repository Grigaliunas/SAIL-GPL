"""`sail` command-line interface (SAIL-GPL §14.3).

    sail sign   ./model/     build the OMS manifest, sign it, write srm/
    sail verify ./model/     check signature, manifest, AIBOM, attestation, CVD
    sail audit  ./release/   walk a tree, report artifacts missing compliant SRM
    sail keygen --out k.key  generate a signing key
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, crypto
from .commands import Report, audit, sign, verify

_GREEN, _RED, _DIM, _RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def _color(enabled: bool):
    if enabled:
        return _GREEN, _RED, _DIM, _RST
    return "", "", "", ""


def _print_report(rep: Report, use_color: bool) -> None:
    g, r, dim, rst = _color(use_color)
    status = f"{g}COMPLIANT{rst}" if rep.ok else f"{r}NON-COMPLIANT{rst}"
    print(f"{rep.target}  {status}")
    for name, ok, detail in rep.checks:
        mark = f"{g}PASS{rst}" if ok else f"{r}FAIL{rst}"
        line = f"  [{mark}] {name}"
        if detail:
            line += f"  {dim}{detail}{rst}"
        print(line)


def _report_to_dict(rep: Report) -> dict:
    return {
        "target": str(rep.target),
        "compliant": rep.ok,
        "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in rep.checks],
    }


def _load_optional_json(arg: str | None):
    if not arg:
        return None
    return json.loads(Path(arg).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #


def cmd_sign(args) -> int:
    model_dir = Path(args.path)
    name = args.model_name or model_dir.resolve().name
    aibom_overrides = _load_optional_json(args.aibom)

    attestation_tests = None
    independent = args.independent
    evaluator = args.evaluator
    spec = _load_optional_json(args.attestation)
    if isinstance(spec, list):
        attestation_tests = spec
    elif isinstance(spec, dict):
        attestation_tests = spec.get("tests")
        independent = spec.get("independent", independent)
        evaluator = spec.get("evaluator", evaluator)

    env = sign(
        model_dir,
        model_name=name,
        model_version=args.model_version,
        tier=args.tier,
        alg=args.alg,
        key_path=Path(args.key) if args.key else None,
        issuer=args.issuer,
        contact=args.contact,
        policy_url=args.policy_url,
        created=args.date,
        evaluator=evaluator,
        aibom_overrides=aibom_overrides,
        attestation_tests=attestation_tests,
        independent=independent,
        transparency_log=args.transparency_log,
    )
    print(f"signed {model_dir}")
    print(f"  alg      {env['crypto_agility']['alg']}"
          f"  (pq={env['crypto_agility']['post_quantum']}, hybrid={env['crypto_agility']['hybrid']})")
    print(f"  key_id   {env['key_id']}")
    print(f"  issuer   {env['issuer']}")
    print(f"  manifest {env['manifest_sha256']}")
    if not env.get("_key_persisted"):
        print("  note: ephemeral key was not saved; re-signing will use a new key "
              "(pass --key to persist).", file=sys.stderr)
    # Confirm the bundle we just wrote actually verifies.
    rep = verify(model_dir)
    if not rep.ok:
        print("WARNING: freshly signed bundle did not verify:", file=sys.stderr)
        _print_report(rep, sys.stderr.isatty())
        return 1
    return 0


def cmd_verify(args) -> int:
    rep = verify(Path(args.path), pq_only=args.pq_only, strict_issuer=args.strict_issuer)
    if args.json:
        print(json.dumps(_report_to_dict(rep), indent=2))
    else:
        _print_report(rep, sys.stdout.isatty())
    return 0 if rep.ok else 1


def cmd_audit(args) -> int:
    reports = audit(Path(args.path))
    if args.json:
        print(json.dumps([_report_to_dict(r) for r in reports], indent=2))
    else:
        if not reports:
            print(f"no model artifacts found under {args.path}")
        for rep in reports:
            _print_report(rep, sys.stdout.isatty())
        n_bad = sum(1 for r in reports if not r.ok)
        print(f"\n{len(reports)} artifact(s), {n_bad} non-compliant")
    return 0 if all(r.ok for r in reports) else 1


def cmd_keygen(args) -> int:
    keyfile = crypto.generate_keyfile(args.alg)
    out = Path(args.out)
    out.write_bytes(keyfile)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"wrote {args.alg} private key to {out}  (keep it secret)")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sail", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"sail {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sign", help="build and sign the SRM bundle")
    s.add_argument("path", help="model directory")
    s.add_argument("--model-name")
    s.add_argument("--model-version", default="1.0.0")
    s.add_argument("--tier", choices=["T1", "T2", "T3"], default="T1")
    s.add_argument("--alg", default=crypto.DEFAULT_ALG,
                   choices=list(crypto.CLASSICAL) + list(crypto.PQ) + ["hybrid"])
    s.add_argument("--key", help="signing key path (created if absent)")
    s.add_argument("--issuer", help="issuer string (default self-signed:<key_id>)")
    s.add_argument("--contact", help="security contact for SECURITY.md (§7.6)")
    s.add_argument("--policy-url", default="https://example.org/security")
    s.add_argument("--date", help="ISO timestamp to stamp (default: none)")
    s.add_argument("--evaluator", default="self-attestation")
    s.add_argument("--independent", action="store_true", help="independent red-team (T3)")
    s.add_argument("--aibom", help="JSON file of AIBOM overrides (§7.2)")
    s.add_argument("--attestation", help="JSON file of attestation tests (§7.4)")
    s.add_argument("--transparency-log", help="transparency-log reference (T3)")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify an SRM bundle")
    v.add_argument("path", help="model directory")
    v.add_argument("--pq-only", action="store_true", help="require post-quantum signature")
    v.add_argument("--strict-issuer", help="require this exact issuer string")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("audit", help="walk a tree and report SRM compliance")
    a.add_argument("path", help="directory tree to audit")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_audit)

    k = sub.add_parser("keygen", help="generate a signing key")
    k.add_argument("--alg", default=crypto.DEFAULT_ALG,
                   choices=list(crypto.CLASSICAL) + list(crypto.PQ) + ["hybrid"])
    k.add_argument("--out", required=True)
    k.set_defaults(func=cmd_keygen)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"sail: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
