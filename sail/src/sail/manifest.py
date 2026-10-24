"""Complete file inventory for the native SAIL SRM v2 format."""

from __future__ import annotations

import re
import stat
from pathlib import Path, PurePosixPath

from . import FORMAT_VERSION, _UNCOVERED
from .canonical import cjson, sha256_bytes, sha256_file

MANIFEST_TYPE = "https://sail-gpl.org/srm/manifest/v2"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def inspect_tree(model_dir: Path) -> list[str]:
    """Reject links and special files, including links rglob will not follow."""
    problems = []
    if not model_dir.is_dir():
        return ["model path must be an existing directory"]
    for p in model_dir.rglob("*"):
        rel = p.relative_to(model_dir).as_posix()
        if p.is_symlink():
            problems.append(f"symbolic link is not allowed: {rel}")
        elif not (stat.S_ISREG(p.lstat().st_mode) or p.is_dir()):
            problems.append(f"special file is not allowed: {rel}")
    return problems


def iter_covered_files(model_dir: Path):
    problems = inspect_tree(model_dir)
    if problems:
        raise ValueError("; ".join(problems))
    return [(p.relative_to(model_dir).as_posix(), p)
            for p in sorted(model_dir.rglob("*"), key=lambda p: p.relative_to(model_dir).as_posix())
            if p.is_file() and p.relative_to(model_dir).as_posix() not in _UNCOVERED]


def contains_private_key(path: Path) -> bool:
    """Detect accidental publication of common PEM and native secret-key files."""
    if path.suffix.lower() == ".key":
        return True
    with path.open("rb") as fh:
        prefix = fh.read(65536)
    return bool(re.search(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", prefix)
                or re.search(rb'"secret_key"\s*:', prefix))


def artifact_digest(model_dir: Path) -> str:
    """Bind evaluator reports to every artifact file outside srm/, including its card."""
    files = [{"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)}
             for rel, path in iter_covered_files(model_dir)
             if not rel.startswith("srm/")]
    if not files:
        raise ValueError("an evaluation requires nonempty model artifact files")
    return sha256_bytes(cjson(files))


def build(model_dir: Path, *, model_name: str, model_version: str,
          created: str, signing: dict, tier: str,
          parent_signature_sha256: str | None = None) -> dict:
    files = []
    for rel, path in iter_covered_files(model_dir):
        if contains_private_key(path):
            raise ValueError(f"private signing material must not be distributed: {rel}")
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    result = {
        "_type": MANIFEST_TYPE, "schema_version": FORMAT_VERSION,
        "model": {"name": model_name, "version": model_version},
        "created": created, "tier": tier, "signing": signing,
        "hash_algorithms": ["sha256"], "file_count": len(files),
        "total_bytes": sum(f["size"] for f in files), "files": files,
        "files_digest": sha256_bytes(cjson(files)),
    }
    if parent_signature_sha256 is not None:
        result["derived_from"] = {"parent_signature_sha256": parent_signature_sha256}
    return result


def check(model_dir: Path, manifest: dict) -> list[str]:
    problems = inspect_tree(model_dir)
    if problems:
        return problems
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    if (manifest.get("_type") != MANIFEST_TYPE
            or manifest.get("schema_version") != FORMAT_VERSION):
        problems.append("unsupported manifest format; re-sign using SAIL SRM v2")
    if manifest.get("hash_algorithms") != ["sha256"]:
        problems.append("hash_algorithms must be [sha256]")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return problems + ["manifest files must be a nonempty array"]
    listed = {}
    for entry in files:
        if not isinstance(entry, dict):
            problems.append("manifest file entry must be an object")
            continue
        rel = entry.get("path")
        if (not isinstance(rel, str) or not rel or "\\" in rel
                or PurePosixPath(rel).is_absolute()
                or any(part in ("", ".", "..") for part in rel.split("/"))
                or rel in _UNCOVERED):
            problems.append("invalid or excluded manifest path")
            continue
        if rel in listed:
            problems.append(f"duplicate manifest path: {rel}")
        listed[rel] = entry
        if not isinstance(entry.get("sha256"), str) or not _HEX.fullmatch(entry["sha256"]):
            problems.append(f"invalid SHA-256: {rel}")
        if type(entry.get("size")) is not int or entry["size"] < 0:
            problems.append(f"invalid file size: {rel}")
    on_disk = dict(iter_covered_files(model_dir))
    for missing in sorted(set(listed) - set(on_disk)):
        problems.append(f"manifest lists missing file: {missing}")
    for extra in sorted(set(on_disk) - set(listed)):
        problems.append(f"unsigned file present, not in manifest: {extra}")
    for rel in sorted(set(listed) & set(on_disk)):
        path, entry = on_disk[rel], listed[rel]
        if contains_private_key(path):
            problems.append(f"private signing material must not be distributed: {rel}")
        if sha256_file(path) != entry.get("sha256"):
            problems.append(f"hash mismatch: {rel}")
        if path.stat().st_size != entry.get("size"):
            problems.append(f"size mismatch: {rel}")
    if manifest.get("files_digest") != sha256_bytes(cjson(files)):
        problems.append("files_digest does not match the file list")
    if type(manifest.get("file_count")) is not int or manifest["file_count"] != len(files):
        problems.append("file_count does not match the file list")
    sizes = [e.get("size") for e in files if isinstance(e, dict)]
    if (type(manifest.get("total_bytes")) is not int
            or any(type(s) is not int for s in sizes)
            or manifest["total_bytes"] != sum(s for s in sizes if type(s) is int)):
        problems.append("total_bytes does not match the file list")
    parent = manifest.get("derived_from")
    if parent is not None and (not isinstance(parent, dict)
            or not isinstance(parent.get("parent_signature_sha256"), str)
            or not _HEX.fullmatch(parent["parent_signature_sha256"])):
        problems.append("derived_from requires a parent signature SHA-256")
    return problems
