"""Independent RFC 6962 reference trees and real signed receipt checks."""

from copy import deepcopy
import hashlib

import pytest

from sail import crypto, transparency
from sail.canonical import cjson, sha256_bytes


# Reference implementation uses the recursive RFC 6962 split definition,
# independently of the iterative inclusion_root implementation under test.
def reference_leaf(data):
    return hashlib.sha256(b"\x00" + hashlib.sha256(data).digest()).digest()


def reference_tree(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + reference_tree(leaves[:split]) + reference_tree(leaves[split:])).digest()


def reference_path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return reference_path(leaves[:split], index) + [reference_tree(leaves[split:])]
    return reference_path(leaves[split:], index - split) + [reference_tree(leaves[:split])]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 23, 31, 33, 65])
def test_inclusion_matches_independent_recursive_tree_at_every_index(size):
    data = [f"manifest-{index}".encode() for index in range(size)]
    leaves = [reference_leaf(value) for value in data]
    expected = reference_tree(leaves)
    for index in range(size):
        assert transparency.leaf_hash(data[index]) == leaves[index]
        assert transparency.inclusion_root(leaves[index], index, size, reference_path(leaves, index)) == expected


@pytest.fixture
def log_key():
    return crypto.generate_keyfile("ed25519")


def make_receipt(key, *, size=5, index=3):
    data = [f"manifest-{number}".encode() for number in range(size)]
    leaves = [reference_leaf(value) for value in data]
    descriptor = crypto.public_descriptor("ed25519", key)
    checkpoint = {
        "_type": transparency.CHECKPOINT_TYPE,
        "log_id": descriptor["key_id"],
        "issued_at": "2026-10-24T12:00:00Z",
        "tree_size": size,
        "root_hash": reference_tree(leaves).hex(),
    }
    proof = {
        "_type": transparency.RECEIPT_TYPE,
        "schema_version": "2",
        "manifest_sha256": sha256_bytes(data[index]),
        "leaf_index": index,
        "audit_path": [sibling.hex() for sibling in reference_path(leaves, index)],
        "checkpoint": checkpoint,
        "signature": crypto.sign("ed25519", key, cjson(checkpoint)),
    }
    return proof, data[index], descriptor


def resign(proof, key):
    proof["signature"] = crypto.sign("ed25519", key, cjson(proof["checkpoint"]))


@pytest.mark.parametrize("size", [1, 3, 5, 6, 7, 9, 17])
def test_signed_receipts_verify_all_positions_in_irregular_trees(log_key, size):
    for index in range(size):
        proof, manifest, trusted = make_receipt(log_key, size=size, index=index)
        assert transparency.check(proof, manifest, trusted) == []


def test_receipt_requires_external_log_key_and_matching_manifest(log_key):
    proof, manifest, trusted = make_receipt(log_key)
    assert transparency.check(proof, manifest, None)
    other_key = crypto.public_descriptor("ed25519", crypto.generate_keyfile("ed25519"))
    assert transparency.check(proof, manifest, other_key)
    assert transparency.check(proof, manifest + b"changed", trusted)
    proof["manifest_sha256"] = "ab" * 32
    assert transparency.check(proof, manifest, trusted)


@pytest.mark.parametrize("field,value", [
    ("tree_size", 6), ("root_hash", "ab" * 32),
    ("issued_at", "2026-10-25T12:00:00Z"), ("log_id", "ab" * 32),
])
def test_checkpoint_mutation_invalidates_its_signature(log_key, field, value):
    proof, manifest, trusted = make_receipt(log_key)
    proof["checkpoint"][field] = value
    assert transparency.check(proof, manifest, trusted)


@pytest.mark.parametrize("field,value", [
    ("tree_size", 0), ("tree_size", -1), ("tree_size", True), ("tree_size", False),
    ("tree_size", "5"), ("tree_size", None), ("tree_size", []), ("tree_size", {}),
    ("root_hash", "AB" * 32), ("root_hash", "ab"), ("root_hash", []),
    ("root_hash", None), ("log_id", "ab" * 32), ("log_id", []),
    ("issued_at", True), ("issued_at", "2026-10-24T12:00:00+03:00"),
    ("issued_at", "not a date"), ("issued_at", None),
])
def test_validly_signed_malformed_checkpoints_fail_closed(log_key, field, value):
    proof, manifest, trusted = make_receipt(log_key)
    proof["checkpoint"][field] = value
    resign(proof, log_key)
    assert transparency.check(proof, manifest, trusted)


@pytest.mark.parametrize("index", [True, False, None, -1, 5, 6, "3", [], {}])
def test_invalid_leaf_indices_fail_closed(log_key, index):
    proof, manifest, trusted = make_receipt(log_key)
    proof["leaf_index"] = index
    assert transparency.check(proof, manifest, trusted)


@pytest.mark.parametrize("path", [None, {}, "not a list", [None], [[]], [{}], [True],
                                   ["ab"], ["AB" * 32], ["zz" * 32], ["ab" * 32] * 65])
def test_malformed_audit_paths_fail_closed(log_key, path):
    proof, manifest, trusted = make_receipt(log_key)
    proof["audit_path"] = path
    assert transparency.check(proof, manifest, trusted)


def test_incomplete_extra_and_wrong_audit_paths_are_rejected(log_key):
    proof, manifest, trusted = make_receipt(log_key)
    incomplete = deepcopy(proof)
    incomplete["audit_path"].pop()
    assert transparency.check(incomplete, manifest, trusted)
    extra = deepcopy(proof)
    extra["audit_path"].append("ab" * 32)
    assert transparency.check(extra, manifest, trusted)
    wrong = deepcopy(proof)
    wrong["audit_path"][0] = "ab" * 32
    assert transparency.check(wrong, manifest, trusted)


@pytest.mark.parametrize("value", [None, [], "value", 42, True])
def test_malformed_top_level_or_nested_receipt_types_fail_closed(log_key, value):
    proof, manifest, trusted = make_receipt(log_key)
    assert transparency.check(value, manifest, trusted)
    for field in ("checkpoint", "signature"):
        mutated = deepcopy(proof)
        mutated[field] = value
        assert transparency.check(mutated, manifest, trusted)
    assert transparency.check(proof, manifest, value)


def test_receipt_schema_and_required_fields_are_not_inferred(log_key):
    proof, manifest, trusted = make_receipt(log_key)
    for field in proof:
        mutated = deepcopy(proof)
        del mutated[field]
        assert transparency.check(mutated, manifest, trusted)
    proof["schema_version"] = True
    assert transparency.check(proof, manifest, trusted)


@pytest.mark.parametrize("index,size", [(False, 1), (0, True), (0, 0), (1, 1), (-1, 1)])
def test_low_level_inclusion_rejects_invalid_integer_inputs(index, size):
    with pytest.raises(ValueError):
        transparency.inclusion_root(b"\x00" * 32, index, size, [])
