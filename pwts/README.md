# PWTS 

```
PWTS reference implementation using BW6-761 Groth16 to constrain
BLS12-377 operations.

| File | Function |
|---|---|
| `circuit.go` | Selection relation and per-signer signature checks |
| `audit.go` | DKG, threshold opening, share refresh, and handover |
| `reference_verifier.go` | Context binding, proof, and aggregate-signature verification |
| `local_service.go` | Interface to the system testbed |
```

```sh
Requires Go 1.25.7 or later. Dependencies are pinned in `go.mod` and `go.sum`.

Run from this directory:

go run . -sizes 4,8,12,16 -out results
go run . -audit-only -sizes 4,8,12,16 -out results_audit
go run ./cmd/audit_payload
```

```
## Benchmark Notes

Proof generation, native-signature verification, and full verification
are measured separately. Memory reporting uses process memory on Windows
and Go runtime memory on other platforms.

## Audit Assumptions

The audit protocol assumes authenticated broadcast, private channels,
and secure erasure. Setup and session keys are generated locally for experiments.
```