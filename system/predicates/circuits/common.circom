pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Binary Poseidon Merkle inclusion. pathBits[i]=0 means the running node is
// the left child; pathBits[i]=1 means it is the right child.
template MerklePathPoseidon(levels) {
    signal input leaf;
    signal input siblings[levels];
    signal input pathBits[levels];
    signal output root;

    signal nodes[levels + 1];
    signal left[levels];
    signal right[levels];
    component h[levels];

    nodes[0] <== leaf;
    for (var i = 0; i < levels; i++) {
        pathBits[i] * (pathBits[i] - 1) === 0;
        left[i] <== nodes[i] + pathBits[i] * (siblings[i] - nodes[i]);
        right[i] <== siblings[i] + pathBits[i] * (nodes[i] - siblings[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];
        nodes[i + 1] <== h[i].out;
    }
    root <== nodes[levels];
}

// Computes two roots over the same path. Used to constrain a revocation leaf
// transition from 0 to 1 without exposing the credential identifier.
template DualMerklePathPoseidon(levels) {
    signal input oldLeaf;
    signal input newLeaf;
    signal input siblings[levels];
    signal input pathBits[levels];
    signal output oldRoot;
    signal output newRoot;

    signal oldNodes[levels + 1];
    signal newNodes[levels + 1];
    signal oldLeft[levels];
    signal oldRight[levels];
    signal newLeft[levels];
    signal newRight[levels];
    component oldHash[levels];
    component newHash[levels];

    oldNodes[0] <== oldLeaf;
    newNodes[0] <== newLeaf;
    for (var i = 0; i < levels; i++) {
        pathBits[i] * (pathBits[i] - 1) === 0;

        oldLeft[i] <== oldNodes[i] + pathBits[i] * (siblings[i] - oldNodes[i]);
        oldRight[i] <== siblings[i] + pathBits[i] * (oldNodes[i] - siblings[i]);
        oldHash[i] = Poseidon(2);
        oldHash[i].inputs[0] <== oldLeft[i];
        oldHash[i].inputs[1] <== oldRight[i];
        oldNodes[i + 1] <== oldHash[i].out;

        newLeft[i] <== newNodes[i] + pathBits[i] * (siblings[i] - newNodes[i]);
        newRight[i] <== siblings[i] + pathBits[i] * (newNodes[i] - siblings[i]);
        newHash[i] = Poseidon(2);
        newHash[i].inputs[0] <== newLeft[i];
        newHash[i].inputs[1] <== newRight[i];
        newNodes[i + 1] <== newHash[i].out;
    }
    oldRoot <== oldNodes[levels];
    newRoot <== newNodes[levels];
}
