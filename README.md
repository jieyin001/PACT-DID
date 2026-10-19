# PACT-DID

Research prototype for accountable cross-domain DID authorization.

| Directory | Scope |
|---|---|
| `pwts/` | Full selection relation, per-signer validity checks, reference verifier, audit lifecycle |
| `system/deployment/` | Single-host FISCO BCOS + Besu testbed and Veramo-based verification |
| `system/predicates/` | Registration, issuer authorization and credential-status circuits |
| `system/vti/` | Synthetic VTI incentive and recovery experiments |

See [PWTS instructions](pwts/README.md) and [system instructions](system/README.md).

```
## Experimental Setup

The dual-chain testbed runs on a single host with logical committee members
and a minimal MaskID-compatible source adapter. It supports cross-domain
VC issuance. Business-predicate and audit-lifecycle benchmarks run separately.

The PWTS benchmark uses all committee members as signers (`n = k`).
Audit committee size and selected signer count are configured separately.

## Repository Notes

Results, generated keys, and binaries are excluded. See the component
instructions to reproduce the experiments.

This repository contains experimental research code. Do not commit deployment
secrets. Dependency licenses apply; a repository license has not yet been selected.
```