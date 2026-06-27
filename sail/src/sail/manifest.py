"""OMS-style manifest over all model files (SAIL-GPL §7.1).

The manifest is the signed payload. It hashes every file in the model
directory except the two SRM files that cannot hash themselves
(`srm/manifest.json`, the payload, and `srm/model.sig`, the signature). That
deliberately pulls the AIBOM, the attestation, the model card and SECURITY.md
under the same signature, so the whole bundle is integrity-bound, not just the
weights.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import _UNCOVERED, SRM_DIR
from .canonical import HASH_ALG, cjson, sha256_bytes, sha256_file

MANIFEST_TYPE = "https://sail-gpl.org/srm/manifest/v1"


def iter_covered_files(model_dir: Path):
    """Yield (relposix, Path) for every file the manifest must cover, sorted."""
    out = []
    for p in sorted(model_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(model_dir).as_posix()
        if rel in _UNCOVERED:
            continue
        out.append((rel, p))
    out.sort(key=lambda t: t[0])
    return out


def build(model_dir: Path, *, model_name: str, model_version: str,
          created: Optional[str] = None, parent_signature_sha256: Optional[str] = None) -> dict:
    files = []
    total = 0
    for rel, path in iter_covered_files(model_dir):
        size = path.stat().st_size
        total += size
        files.append({"path": rel, "size": size, HASH_ALG: sha256_file(path)})
    # A single digest over the file list — the "merkle root" a verifier can
    # quote without re-listing every entry.
    files_digest = sha256_bytes(cjson(files))
    manifest = {
        "_type": MANIFEST_TYPE,
        "spec": "OMS-compatible",
        "model": {"name": model_name, "version": model_version},
        "created": created,
        "hash_algorithms": [HASH_ALG],
        "file_count": len(files),
        "total_bytes": total,
        "files": files,
        "files_digest": files_digest,
    }
    if parent_signature_sha256:
        # §7.8: a derivative records the parent it was signed from.
        manifest["derived_from"] = {"parent_signature_sha256": parent_signature_sha256}
    return manifest


def check(model_dir: Path, manifest: dict) -> list[str]:
    """Return a list of problems; empty list means the manifest matches disk."""
    problems = []
    listed = {f["path"]: f for f in manifest.get("files", [])}
    on_disk = {rel for rel, _ in iter_covered_files(model_dir)}

    for missing in sorted(set(listed) - on_disk):
        problems.append(f"manifest lists missing file: {missing}")
    for extra in sorted(on_disk - set(listed)):
        # An unsigned file smuggled into the bundle is a completeness failure.
        problems.append(f"unsigned file present, not in manifest: {extra}")

    for rel in sorted(set(listed) & on_disk):
        actual = sha256_file(model_dir / rel)
        if actual != listed[rel].get(HASH_ALG):
            problems.append(f"hash mismatch: {rel}")

    if manifest.get("files_digest") != sha256_bytes(cjson(manifest.get("files", []))):
        problems.append("files_digest does not match the file list")
    return problems
