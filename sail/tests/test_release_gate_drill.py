"""Temporary intentional failure for the production release-gate drill."""

import pytest


def test_production_release_gate_blocks_failed_ci():
    pytest.fail("Intentional release-gate drill: production must retain its prior release.")
