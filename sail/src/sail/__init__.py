"""SAIL-GPL technical evidence verification for Super AI model releases."""

__version__ = "1.1.0"
FORMAT_VERSION = "2"
LICENSE_ID = "LicenseRef-SAIL-GPL-1.0"

# Native SAIL SRM v2 file names.
SRM_DIR = "srm"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "model.sig"
AIBOM_NAME = "saibom.json"
ATTESTATION_NAME = "security-attestation.json"
SECURITY_NAME = "SECURITY.md"
MODEL_CARD_NAME = "MODEL_CARD.md"
TRANSPARENCY_NAME = "transparency.json"

# Files that live inside srm/ but are never themselves covered by the manifest
# (manifest.json is the signed payload; model.sig is the detached signature).
_UNCOVERED = {f"{SRM_DIR}/{MANIFEST_NAME}", f"{SRM_DIR}/{SIGNATURE_NAME}",
              f"{SRM_DIR}/{TRANSPARENCY_NAME}"}
