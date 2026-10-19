import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const cases = [
  { name: "registration", id: "tampered-controller-signature", mutate: (x) => { x.sigS = (BigInt(x.sigS) + 1n).toString(); } },
  { name: "registration", id: "tampered-source-inclusion-path", mutate: (x) => { x.siblings[0] = (BigInt(x.siblings[0]) + 1n).toString(); } },
  { name: "issuance", id: "tampered-credential-root-path", mutate: (x) => { x.credentialSiblings[3] = (BigInt(x.credentialSiblings[3]) + 1n).toString(); } },
  { name: "issuance", id: "tampered-source-evidence-path", mutate: (x) => { x.sourceSiblings[7] = (BigInt(x.sourceSiblings[7]) + 1n).toString(); } },
  { name: "revocation", id: "non-incrementing-sequence", mutate: (x) => { x.newSequence = x.oldSequence; } },
  { name: "revocation", id: "tampered-root-transition-path", mutate: (x) => { x.siblings[5] = (BigInt(x.siblings[5]) + 1n).toString(); } },
];

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "crossdid-negative-"));
const results = [];
try {
  for (let i = 0; i < cases.length; i++) {
    const test = cases[i];
    const input = JSON.parse(await fs.readFile(`inputs/${test.name}.json`, "utf8"));
    test.mutate(input);
    const inputFile = path.join(temp, `${test.name}-${i}.json`);
    const witnessFile = path.join(temp, `${test.name}-${i}.wtns`);
    await fs.writeFile(inputFile, JSON.stringify(input));
    const run = spawnSync(
      process.execPath,
      [`build/${test.name}/${test.name}_js/generate_witness.js`,
       `build/${test.name}/${test.name}_js/${test.name}.wasm`, inputFile, witnessFile],
      { encoding: "utf8" },
    );
    const rejected = run.status !== 0;
    results.push({ relation: test.name, case: test.id, rejected });
    console.log(`${test.name} / ${test.id}: ${rejected ? "REJECTED" : "UNEXPECTEDLY ACCEPTED"}`);
    if (!rejected) process.exitCode = 1;
  }
} finally {
  await fs.rm(temp, { recursive: true, force: true });
}

await fs.mkdir("results", { recursive: true });
await fs.writeFile("results/negative_tests.json", JSON.stringify(results, null, 2));
