"""Strict local JSON and base64 regression tests."""

import math

import pytest

from sail.canonical import b64d, b64e, cjson, load_json, sha256_bytes, sha256_file


def test_canonical_unicode_integer_and_key_order_roundtrip():
    value = {"ž": "Unicode", "z": [None, True, False, -12, 0], "a": {"b": "\n"}}
    expected = '{"a":{"b":"\\n"},"z":[null,true,false,-12,0],"ž":"Unicode"}'.encode()
    assert cjson(value) == expected
    assert load_json(expected) == value
    assert cjson(load_json(' { "ž":"Unicode", "a":{"b":"\\n"}, "z":[null,true,false,-12,0]}')) == expected


def test_key_order_is_unicode_codepoint_and_text_is_not_normalized():
    assert cjson({"\U0001f600": 1, "\ue000": 2}) == '{"\ue000":2,"😀":1}'.encode()
    assert cjson("é") != cjson("e\u0301")


@pytest.mark.parametrize("value", [0.0, 1.25, math.nan, math.inf, -math.inf, (), {1: "x"}, b"x", {"n": 1.0}])
def test_canonical_rejects_unsupported_types(value):
    with pytest.raises(ValueError):
        cjson(value)


@pytest.mark.parametrize("text", [
    '{"a":1,"a":2}', '{"a":{"x":1,"x":2}}', '{"a":1,"\\u0061":2}',
    '1.0', '1e2', '-0.0', 'NaN', 'Infinity', '-Infinity', '{"a":NaN}',
    '{"s":"\\ud800"}', '{"\\udfff":0}', '\ufeff{}',
])
def test_strict_parser_rejects_duplicate_keys_floats_and_invalid_unicode(text):
    with pytest.raises(ValueError):
        load_json(text)


@pytest.mark.parametrize("data", [b'"\xff"', b'\xff\xfe{\x00}\x00', b'\xef\xbb\xbf{}', bytearray(b"{}"), 12])
def test_strict_parser_requires_utf8_text_or_bytes(data):
    with pytest.raises(ValueError):
        load_json(data)


def test_canonical_rejects_unpaired_surrogates_and_cycles():
    for value in ["\ud800", {"\udfff": 1}]:
        with pytest.raises(ValueError):
            cjson(value)
    value = []
    value.append(value)
    with pytest.raises(ValueError, match="cyclic"):
        cjson(value)


def test_reused_list_is_not_a_cycle():
    item = [1]
    assert cjson([item, item]) == b"[[1],[1]]"


@pytest.mark.parametrize("text", ["Zg", "Zg===", "Zg==\n", "Z g==", "Zh==", "!!!!", "é", None, b"Zg=="])
def test_base64_rejects_invalid_or_noncanonical_encodings(text):
    with pytest.raises(ValueError):
        b64d(text)


@pytest.mark.parametrize("value", [b"", b"f", b"fo", b"foo", bytes(range(256))])
def test_base64_roundtrip(value):
    assert b64d(b64e(value)) == value


def test_sha256_file_streaming(tmp_path):
    value = b"abc" * (1024 * 1024)
    path = tmp_path / "large.bin"
    path.write_bytes(value)
    assert sha256_file(path) == sha256_bytes(value)
