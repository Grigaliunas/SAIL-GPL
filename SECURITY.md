# Security policy

## Reporting

For sensitive reports, use the repository's private vulnerability reporting
route when GitHub makes it available:
https://github.com/Grigaliunas/SAIL-GPL/security/advisories/new

If private reporting is unavailable, request a private contact channel through
the maintainer's public profile: https://github.com/Grigaliunas. Do not publish
exploit details or sensitive model artifacts in a public issue while arranging
that channel. This document does not promise a monitored mailbox or a response SLA.

## CVD process

The maintainer reviews a received report, confirms scope, discusses reproduction
steps privately, and coordinates a fix and disclosure timing with the reporter.
Record affected versions and preserve reproducible evidence. Downstream model
stewards must publish their own working reporting route, triage reports and
coordinate fixes for their releases.

## Verification scope

The toolkit verifies cryptographic integrity and required release evidence.
It cannot prove that a reporting endpoint is monitored, an evaluator is
organizationally independent or a model is safe. Reports about these limits
are welcome alongside implementation defects.
