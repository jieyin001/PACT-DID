pragma circom 2.1.6;

include "./common.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template RevocationPredicate(levels) {
    signal input objectDigest;
    signal input evidenceDigest;
    signal input contextDigest;
    signal input oldRoot;
    signal input newRoot;
    signal input oldSequence;
    signal input newSequence;
    signal input sourceId;
    signal input targetId;
    signal input epoch;
    signal input revocationPolicy;
    signal input authorityAx;
    signal input authorityAy;

    signal input cid;
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input siblings[levels];

    // Range constraints make seq'=seq+1 an integer statement rather than a
    // field-wrap statement.
    component oldSeqBits = Num2Bits(64);
    component newSeqBits = Num2Bits(64);
    oldSeqBits.in <== oldSequence;
    newSeqBits.in <== newSequence;
    newSequence === oldSequence + 1;

    component cidBits = Num2Bits_strict();
    cidBits.in <== cid;

    component oldLeaf = Poseidon(3);
    oldLeaf.inputs[0] <== 1301;
    oldLeaf.inputs[1] <== cid;
    oldLeaf.inputs[2] <== 0;
    component newLeaf = Poseidon(3);
    newLeaf.inputs[0] <== 1301;
    newLeaf.inputs[1] <== cid;
    newLeaf.inputs[2] <== 1;

    component transition = DualMerklePathPoseidon(levels);
    transition.oldLeaf <== oldLeaf.out;
    transition.newLeaf <== newLeaf.out;
    for (var i = 0; i < levels; i++) {
        transition.siblings[i] <== siblings[i];
        transition.pathBits[i] <== cidBits.out[i];
    }
    transition.oldRoot === oldRoot;
    transition.newRoot === newRoot;

    component authMsg = Poseidon(8);
    authMsg.inputs[0] <== 1302;
    authMsg.inputs[1] <== cid;
    authMsg.inputs[2] <== oldRoot;
    authMsg.inputs[3] <== newRoot;
    authMsg.inputs[4] <== newSequence;
    authMsg.inputs[5] <== sourceId;
    authMsg.inputs[6] <== targetId;
    authMsg.inputs[7] <== revocationPolicy;

    component auth = EdDSAPoseidonVerifier();
    auth.enabled <== 1;
    auth.Ax <== authorityAx;
    auth.Ay <== authorityAy;
    auth.S <== sigS;
    auth.R8x <== sigR8x;
    auth.R8y <== sigR8y;
    auth.M <== authMsg.out;

    component ev0 = Poseidon(8);
    ev0.inputs[0] <== 1303;
    ev0.inputs[1] <== authMsg.out;
    ev0.inputs[2] <== sigR8x;
    ev0.inputs[3] <== sigR8y;
    ev0.inputs[4] <== sigS;
    ev0.inputs[5] <== oldRoot;
    ev0.inputs[6] <== newRoot;
    ev0.inputs[7] <== newSequence;

    signal evAcc[levels + 1];
    component evHash[levels];
    evAcc[0] <== ev0.out;
    for (var j = 0; j < levels; j++) {
        evHash[j] = Poseidon(2);
        evHash[j].inputs[0] <== evAcc[j];
        evHash[j].inputs[1] <== siblings[j];
        evAcc[j + 1] <== evHash[j].out;
    }
    evAcc[levels] === evidenceDigest;

    component obj = Poseidon(4);
    obj.inputs[0] <== 1304;
    obj.inputs[1] <== newRoot;
    obj.inputs[2] <== newSequence;
    obj.inputs[3] <== evidenceDigest;
    obj.out === objectDigest;

    component ctx = Poseidon(6);
    ctx.inputs[0] <== 1001;
    ctx.inputs[1] <== 3;
    ctx.inputs[2] <== epoch;
    ctx.inputs[3] <== sourceId;
    ctx.inputs[4] <== targetId;
    ctx.inputs[5] <== revocationPolicy;
    ctx.out === contextDigest;
}

component main {public [objectDigest, evidenceDigest, contextDigest,
    oldRoot, newRoot, oldSequence, newSequence, sourceId, targetId,
    epoch, revocationPolicy, authorityAx, authorityAy]} = RevocationPredicate(32);

