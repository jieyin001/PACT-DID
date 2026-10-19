import fs from "node:fs/promises";
import path from "node:path";
import { buildEddsa, buildPoseidon } from "circomlibjs";

const poseidon = await buildPoseidon();
const F = poseidon.F;
const eddsa = await buildEddsa();

const H = (xs) => BigInt(F.toObject(poseidon(xs.map(BigInt))));
const dec = (x) => BigInt(F.toObject(x)).toString();
const ds = (xs) => xs.map((x) => BigInt(x).toString());
const key = (seed) => Buffer.from(Array.from({ length: 32 }, (_, i) => (seed + 17 * i) & 0xff));

function publicKey(privateKey) {
  const A = eddsa.prv2pub(privateKey);
  return [BigInt(F.toObject(A[0])), BigInt(F.toObject(A[1]))];
}

function signature(privateKey, message) {
  const sig = eddsa.signPoseidon(privateKey, F.e(message));
  return {
    R8x: BigInt(F.toObject(sig.R8[0])),
    R8y: BigInt(F.toObject(sig.R8[1])),
    S: BigInt(sig.S),
  };
}

function siblings(tag, levels) {
  return Array.from({ length: levels }, (_, i) => H([tag, i + 1, (i + 1) * 97]));
}

function pathBits(index, levels) {
  const value = BigInt(index);
  return Array.from({ length: levels }, (_, i) => Number((value >> BigInt(i)) & 1n));
}

function merkleRoot(leaf, sibs, bits) {
  let node = leaf;
  for (let i = 0; i < sibs.length; i++) {
    node = bits[i] === 0 ? H([node, sibs[i]]) : H([sibs[i], node]);
  }
  return node;
}

function evidenceFold(seed, sibs, bits = null) {
  let acc = seed;
  for (let i = 0; i < sibs.length; i++) {
    acc = bits ? H([acc, sibs[i], bits[i]]) : H([acc, sibs[i]]);
  }
  return acc;
}

async function registrationInput() {
  const levels = 20;
  const did = 10001n;
  const userPkHash = H([20001n, 20002n]);
  const metaHash = H([30001n, 30002n, 30003n]);
  const version = 7n;
  const sourceId = 101n;
  const targetId = 202n;
  const epoch = 5n;
  const finalityPolicy = 12n;
  const finalityCheckpoint = H([40001n, sourceId, version]);
  const controllerPrivate = key(11);
  const [controllerAx, controllerAy] = publicKey(controllerPrivate);

  const authMsg = H([1101n, did, userPkHash, metaHash, version, sourceId, targetId]);
  const sig = signature(controllerPrivate, authMsg);
  const leaf = H([1102n, authMsg, controllerAx, controllerAy]);
  const sibs = siblings(5101n, levels);
  const bits = pathBits(0x5a31n, levels);
  const sourceRoot = merkleRoot(leaf, sibs, bits);
  const ev0 = H([1103n, authMsg, sig.R8x, sig.R8y, sig.S,
    sourceRoot, finalityCheckpoint, finalityPolicy]);
  const evidenceDigest = evidenceFold(ev0, sibs, bits);
  const objectDigest = H([1104n, did, userPkHash, metaHash, version,
    sourceId, targetId, evidenceDigest]);
  const contextDigest = H([1001n, 1n, epoch, sourceId, targetId, finalityPolicy]);

  return {
    objectDigest: objectDigest.toString(), evidenceDigest: evidenceDigest.toString(),
    contextDigest: contextDigest.toString(), did: did.toString(),
    userPkHash: userPkHash.toString(), metaHash: metaHash.toString(),
    version: version.toString(), sourceId: sourceId.toString(),
    targetId: targetId.toString(), epoch: epoch.toString(),
    finalityPolicy: finalityPolicy.toString(), sourceRoot: sourceRoot.toString(),
    finalityCheckpoint: finalityCheckpoint.toString(),
    controllerAx: controllerAx.toString(), controllerAy: controllerAy.toString(),
    sigR8x: sig.R8x.toString(), sigR8y: sig.R8y.toString(), sigS: sig.S.toString(),
    siblings: ds(sibs), pathBits: ds(bits),
  };
}

async function issuanceInput() {
  const levels = 20;
  const sourceId = 101n;
  const targetId = 202n;
  const epoch = 5n;
  const issuancePolicy = 22n;
  const holderPkHash = H([60001n, 60002n]);
  const commitments = [
    H([61001n, 1n]), H([61001n, 2n]), H([61001n, 3n]), H([61001n, 4n]),
  ];
  const issuerPrivate = key(29);
  const [issuerAx, issuerAy] = publicKey(issuerPrivate);
  const claimsDigest = H([1201n, ...commitments]);
  const credentialLeaf = H([1202n, claimsDigest, holderPkHash, issuerAx]);
  const credentialSiblings = siblings(6201n, levels);
  const credentialBits = pathBits(0x3c91n, levels);
  const credentialRoot = merkleRoot(credentialLeaf, credentialSiblings, credentialBits);

  const sourceEvidenceLeaf = H([6301n, issuerAx, claimsDigest, issuancePolicy]);
  const sourceSiblings = siblings(6302n, levels);
  const sourceBits = pathBits(0x7123n, levels);
  const sourceStateRoot = merkleRoot(sourceEvidenceLeaf, sourceSiblings, sourceBits);

  const authMsg = H([1203n, claimsDigest, credentialRoot, sourceEvidenceLeaf,
    holderPkHash, sourceId, targetId, issuancePolicy]);
  const sig = signature(issuerPrivate, authMsg);
  const ev0 = H([1204n, authMsg, sig.R8x, sig.R8y, sig.S,
    credentialRoot, sourceStateRoot, sourceEvidenceLeaf]);
  let evidenceDigest = evidenceFold(ev0, credentialSiblings, credentialBits);
  evidenceDigest = evidenceFold(evidenceDigest, sourceSiblings, sourceBits);
  const issuerKeyHash = H([issuerAx, issuerAy]);
  const objectDigest = H([1205n, credentialRoot, sourceId, targetId,
    issuerKeyHash, evidenceDigest]);
  const contextDigest = H([1001n, 2n, epoch, sourceId, targetId, issuancePolicy]);

  return {
    objectDigest: objectDigest.toString(), evidenceDigest: evidenceDigest.toString(),
    contextDigest: contextDigest.toString(), credentialRoot: credentialRoot.toString(),
    sourceStateRoot: sourceStateRoot.toString(), sourceId: sourceId.toString(),
    targetId: targetId.toString(), epoch: epoch.toString(),
    issuancePolicy: issuancePolicy.toString(), issuerAx: issuerAx.toString(),
    issuerAy: issuerAy.toString(), holderPkHash: holderPkHash.toString(),
    commitments: ds(commitments), sourceEvidenceLeaf: sourceEvidenceLeaf.toString(),
    sigR8x: sig.R8x.toString(), sigR8y: sig.R8y.toString(), sigS: sig.S.toString(),
    credentialSiblings: ds(credentialSiblings), credentialPathBits: ds(credentialBits),
    sourceSiblings: ds(sourceSiblings), sourcePathBits: ds(sourceBits),
  };
}

async function revocationInput() {
  const levels = 32;
  const cid = 0x1234abcden;
  const oldSequence = 41n;
  const newSequence = oldSequence + 1n;
  const sourceId = 101n;
  const targetId = 202n;
  const epoch = 5n;
  const revocationPolicy = 32n;
  const authorityPrivate = key(47);
  const [authorityAx, authorityAy] = publicKey(authorityPrivate);
  const bits = pathBits(cid, levels);
  const sibs = siblings(7101n, levels);
  const oldLeaf = H([1301n, cid, 0n]);
  const newLeaf = H([1301n, cid, 1n]);
  const oldRoot = merkleRoot(oldLeaf, sibs, bits);
  const newRoot = merkleRoot(newLeaf, sibs, bits);
  const authMsg = H([1302n, cid, oldRoot, newRoot, newSequence,
    sourceId, targetId, revocationPolicy]);
  const sig = signature(authorityPrivate, authMsg);
  const ev0 = H([1303n, authMsg, sig.R8x, sig.R8y, sig.S,
    oldRoot, newRoot, newSequence]);
  const evidenceDigest = evidenceFold(ev0, sibs);
  const objectDigest = H([1304n, newRoot, newSequence, evidenceDigest]);
  const contextDigest = H([1001n, 3n, epoch, sourceId, targetId, revocationPolicy]);

  return {
    objectDigest: objectDigest.toString(), evidenceDigest: evidenceDigest.toString(),
    contextDigest: contextDigest.toString(), oldRoot: oldRoot.toString(),
    newRoot: newRoot.toString(), oldSequence: oldSequence.toString(),
    newSequence: newSequence.toString(), sourceId: sourceId.toString(),
    targetId: targetId.toString(), epoch: epoch.toString(),
    revocationPolicy: revocationPolicy.toString(), authorityAx: authorityAx.toString(),
    authorityAy: authorityAy.toString(), cid: cid.toString(),
    sigR8x: sig.R8x.toString(), sigR8y: sig.R8y.toString(), sigS: sig.S.toString(),
    siblings: ds(sibs),
  };
}

const outputDir = path.resolve("inputs");
await fs.mkdir(outputDir, { recursive: true });
await Promise.all([
  fs.writeFile(path.join(outputDir, "registration.json"), JSON.stringify(await registrationInput(), null, 2)),
  fs.writeFile(path.join(outputDir, "issuance.json"), JSON.stringify(await issuanceInput(), null, 2)),
  fs.writeFile(path.join(outputDir, "revocation.json"), JSON.stringify(await revocationInput(), null, 2)),
]);
console.log(`Wrote inputs to ${outputDir}`);
