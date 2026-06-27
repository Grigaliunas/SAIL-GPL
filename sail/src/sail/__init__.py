"""sail — reference toolkit for SAIL-GPL v1.0 Secure-Release Metadata (SRM).

Implements the three commands described in SAIL-GPL §14.3:

    sail sign   ./model/     build the OMS manifest, sign it, write srm/
    sail verify ./model/     check signature, manifest, AIBOM, attestation, CVD
    sail audit  ./release/   walk a tree, report artifacts missing compliant SRM

The bundle layout produced and checked is the one in SAIL-GPL §14.2.
"""

__version__ = "1.0.0"

# Canonical SRM bundle file names (SAIL-GPL §14.2).
SRM_DIR = "srm"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "model.sig"
AIBOM_NAME = "aibom.spdx.json"
ATTESTATION_NAME = "security-attestation.json"
SECURITY_NAME = "SECURITY.md"
MODEL_CARD_NAME = "MODEL_CARD.md"

# Files that live inside srm/ but are never themselves covered by the manifest
# (manifest.json is the signed payload; model.sig is the detached signature).
_UNCOVERED = {f"{SRM_DIR}/{MANIFEST_NAME}", f"{SRM_DIR}/{SIGNATURE_NAME}"}
