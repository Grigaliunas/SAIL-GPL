# SAIL SAI Example Model v1.0.0

A nonfunctional fixture demonstrating native SAIL SRM v2 release evidence.
This artifact has no trained parameters and makes no capability claim.

## Intended use

Inspecting the SAI licensing workflow and testing signed release metadata.

## Out-of-scope use

Production inference, safety decisions and evaluating actual SAI capabilities.

## Limitations

There is no inference implementation or training data. The tiny weights file
exists only to demonstrate hashing. A successful metadata verification does
not make this fixture a useful or secure model.

## Security evaluation

All three minimum evaluations are explicitly reported as not applicable in
srm/security-attestation.json. The reasons explain the absence of an inference
engine, training data and a training pipeline. No successful adversarial test
or independent red-team exercise is claimed.

## License

Draft SAIL-GPL v1.0, identifier LicenseRef-SAIL-GPL-1.0. SAI means Super AI
in this project. It is a terminology choice, not a superhuman capability claim.
See srm/SECURITY.md for the reporting route and CVD process.
