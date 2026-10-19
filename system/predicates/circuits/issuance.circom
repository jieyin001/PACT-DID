pragma circom 2.1.6;

include "./common.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

template IssuancePredicate(levels, nClaims) {
    signal input objectDigest;
    signal input evidenceDigest;
    signal input contextDigest;
    signal input credentialRoot;
    signal input sourceStateRoot;
    signal input sourceId;
    signal input targetId;
    signal input epoch;
    signal input issuancePolicy;
    signal input issuerAx;
    signal input issuerAy;
    signal input holderPkHash;

    signal input commitments[nClaims];
    signal input sourceEvidenceLeaf;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input credentialSiblings[levels];
    signal input credentialPathBits[levels];
    signal input sourceSiblings[levels];
    signal input sourcePathBits[levels];

    component claims = Poseidon(nClaims + 1);
    claims.inputs[0] <== 1201;
    for (var i = 0; i < nClaims; i++) {
        claims.inputs[i + 1] <== commitments[i];
    }

    component credentialLeaf = Poseidon(4);
    credentialLeaf.inputs[0] <== 1202;
    credentialLeaf.inputs[1] <== claims.out;
    credentialLeaf.inputs[2] <== holderPkHash;
    credentialLeaf.inputs[3] <== issuerAx;

    component credentialMembership = MerklePathPoseidon(levels);
    credentialMembership.leaf <== credentialLeaf.out;
    for (var j = 0; j < levels; j++) {
        credentialMembership.siblings[j] <== credentialSiblings[j];
        credentialMembership.pathBits[j] <== credentialPathBits[j];
    }
    credentialMembership.root === credentialRoot;

    component sourceMembership = MerklePathPoseidon(levels);
    sourceMembership.leaf <== sourceEvidenceLeaf;
    for (var k = 0; k < levels; k++) {
        sourceMembership.siblings[k] <== sourceSiblings[k];
        sourceMembership.pathBits[k] <== sourcePathBits[k];
    }
    sourceMembership.root === sourceStateRoot;

    component authMsg = Poseidon(8);
    authMsg.inputs[0] <== 1203;
    authMsg.inputs[1] <== claims.out;
    authMsg.inputs[2] <== credentialRoot;
    authMsg.inputs[3] <== sourceEvidenceLeaf;
    authMsg.inputs[4] <== holderPkHash;
    authMsg.inputs[5] <== sourceId;
    authMsg.inputs[6] <== targetId;
    authMsg.inputs[7] <== issuancePolicy;

    component auth = EdDSAPoseidonVerifier();
    auth.enabled <== 1;
    auth.Ax <== issuerAx;
    auth.Ay <== issuerAy;
    auth.S <== sigS;
    auth.R8x <== sigR8x;
    auth.R8y <== sigR8y;
    auth.M <== authMsg.out;

    component ev0 = Poseidon(8);
    ev0.inputs[0] <== 1204;
    ev0.inputs[1] <== authMsg.out;
    ev0.inputs[2] <== sigR8x;
    ev0.inputs[3] <== sigR8y;
    ev0.inputs[4] <== sigS;
    ev0.inputs[5] <== credentialRoot;
    ev0.inputs[6] <== sourceStateRoot;
    ev0.inputs[7] <== sourceEvidenceLeaf;

    signal evAcc[2 * levels + 1];
    component evCredential[levels];
    component evSource[levels];
    evAcc[0] <== ev0.out;
    for (var p = 0; p < levels; p++) {
        evCredential[p] = Poseidon(3);
        evCredential[p].inputs[0] <== evAcc[p];
        evCredential[p].inputs[1] <== credentialSiblings[p];
        evCredential[p].inputs[2] <== credentialPathBits[p];
        evAcc[p + 1] <== evCredential[p].out;
    }
    for (var q = 0; q < levels; q++) {
        evSource[q] = Poseidon(3);
        evSource[q].inputs[0] <== evAcc[levels + q];
        evSource[q].inputs[1] <== sourceSiblings[q];
        evSource[q].inputs[2] <== sourcePathBits[q];
        evAcc[levels + q + 1] <== evSource[q].out;
    }
    evAcc[2 * levels] === evidenceDigest;

    component issuerKeyHash = Poseidon(2);
    issuerKeyHash.inputs[0] <== issuerAx;
    issuerKeyHash.inputs[1] <== issuerAy;

    component obj = Poseidon(6);
    obj.inputs[0] <== 1205;
    obj.inputs[1] <== credentialRoot;
    obj.inputs[2] <== sourceId;
    obj.inputs[3] <== targetId;
    obj.inputs[4] <== issuerKeyHash.out;
    obj.inputs[5] <== evidenceDigest;
    obj.out === objectDigest;

    component ctx = Poseidon(6);
    ctx.inputs[0] <== 1001;
    ctx.inputs[1] <== 2;
    ctx.inputs[2] <== epoch;
    ctx.inputs[3] <== sourceId;
    ctx.inputs[4] <== targetId;
    ctx.inputs[5] <== issuancePolicy;
    ctx.out === contextDigest;
}

component main {public [objectDigest, evidenceDigest, contextDigest,
    credentialRoot, sourceStateRoot, sourceId, targetId, epoch,
    issuancePolicy, issuerAx, issuerAy, holderPkHash]} = IssuancePredicate(20, 4);

