pragma circom 2.1.6;

include "./common.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";

template RegistrationPredicate(levels) {
    // Public typed object and context.
    signal input objectDigest;
    signal input evidenceDigest;
    signal input contextDigest;
    signal input did;
    signal input userPkHash;
    signal input metaHash;
    signal input version;
    signal input sourceId;
    signal input targetId;
    signal input epoch;
    signal input finalityPolicy;
    signal input sourceRoot;
    signal input finalityCheckpoint;
    signal input controllerAx;
    signal input controllerAy;

    // Private registration evidence.
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input siblings[levels];
    signal input pathBits[levels];

    // H(tag_reg_auth, DID, pk_U, H(meta), version, source, target).
    component authMsg = Poseidon(7);
    authMsg.inputs[0] <== 1101;
    authMsg.inputs[1] <== did;
    authMsg.inputs[2] <== userPkHash;
    authMsg.inputs[3] <== metaHash;
    authMsg.inputs[4] <== version;
    authMsg.inputs[5] <== sourceId;
    authMsg.inputs[6] <== targetId;

    component auth = EdDSAPoseidonVerifier();
    auth.enabled <== 1;
    auth.Ax <== controllerAx;
    auth.Ay <== controllerAy;
    auth.S <== sigS;
    auth.R8x <== sigR8x;
    auth.R8y <== sigR8y;
    auth.M <== authMsg.out;

    // The included leaf is the canonical authorized registration.
    component leafHash = Poseidon(4);
    leafHash.inputs[0] <== 1102;
    leafHash.inputs[1] <== authMsg.out;
    leafHash.inputs[2] <== controllerAx;
    leafHash.inputs[3] <== controllerAy;

    component inclusion = MerklePathPoseidon(levels);
    inclusion.leaf <== leafHash.out;
    for (var i = 0; i < levels; i++) {
        inclusion.siblings[i] <== siblings[i];
        inclusion.pathBits[i] <== pathBits[i];
    }
    inclusion.root === sourceRoot;

    // Bind the complete private path and authorization to E_reg's digest.
    component ev0 = Poseidon(8);
    ev0.inputs[0] <== 1103;
    ev0.inputs[1] <== authMsg.out;
    ev0.inputs[2] <== sigR8x;
    ev0.inputs[3] <== sigR8y;
    ev0.inputs[4] <== sigS;
    ev0.inputs[5] <== sourceRoot;
    ev0.inputs[6] <== finalityCheckpoint;
    ev0.inputs[7] <== finalityPolicy;

    signal evAcc[levels + 1];
    component evHash[levels];
    evAcc[0] <== ev0.out;
    for (var j = 0; j < levels; j++) {
        evHash[j] = Poseidon(3);
        evHash[j].inputs[0] <== evAcc[j];
        evHash[j].inputs[1] <== siblings[j];
        evHash[j].inputs[2] <== pathBits[j];
        evAcc[j + 1] <== evHash[j].out;
    }
    evAcc[levels] === evidenceDigest;

    component obj = Poseidon(8);
    obj.inputs[0] <== 1104;
    obj.inputs[1] <== did;
    obj.inputs[2] <== userPkHash;
    obj.inputs[3] <== metaHash;
    obj.inputs[4] <== version;
    obj.inputs[5] <== sourceId;
    obj.inputs[6] <== targetId;
    obj.inputs[7] <== evidenceDigest;
    obj.out === objectDigest;

    component ctx = Poseidon(6);
    ctx.inputs[0] <== 1001;
    ctx.inputs[1] <== 1;
    ctx.inputs[2] <== epoch;
    ctx.inputs[3] <== sourceId;
    ctx.inputs[4] <== targetId;
    ctx.inputs[5] <== finalityPolicy;
    ctx.out === contextDigest;
}

component main {public [objectDigest, evidenceDigest, contextDigest, did,
    userPkHash, metaHash, version, sourceId, targetId, epoch,
    finalityPolicy, sourceRoot, finalityCheckpoint, controllerAx,
    controllerAy]} = RegistrationPredicate(20);

