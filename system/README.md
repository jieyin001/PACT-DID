# System experiments

```
## Dual-Chain Testbed

Requires Ubuntu, Python 3.12+, Node.js 20+, pnpm, and Go.
The single-host testbed runs four FISCO BCOS 2.x nodes
and four Besu QBFT nodes.

Run from `deployment/`:

​```bash
pnpm install --frozen-lockfile
node init_account.mjs
python3 prepare.py
python3 network.py init
go build -C ../../pwts -o ../system/deployment/equidid-local .

./testbed.sh start
./testbed.sh status
./testbed.sh test
node measure_figures.mjs
./testbed.sh stop
​```

The testbed supports cross-domain VC issuance through a source adapter
and a Veramo plugin. Source state is obtained through trusted RPC.
The local service verifies PWTS proofs, and the target contract checks
submitter authorization. Confirmation requires matching receipt block
hashes from three nodes. Online latency excludes setup.
```

\## Business Predicates  Run from 

```
predicates/
```

:  

```
pnpm install --frozen-lockfile
pnpm inputs
pnpm build
pnpm negative
pnpm benchmark
```

  Standalone BN254 Groth16 circuits cover registration authorization, issuer authorization and membership, and credential-status transitions. Timing includes witness generation and proving, with setup excluded and verification performed natively.  ## VTI Simulation  Run from 

```
vti/
```

:  

```
python -m pip install -r requirements.txt
python run_vti_experiments.py
python correct_dynamic_recovery.py
```

  Synthetic VTI experiments record parameters and random seeds with their outputs. Updated event-driven recovery results are saved in 

```
results_recovery_corrected/
```

.