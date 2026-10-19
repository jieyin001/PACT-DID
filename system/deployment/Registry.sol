// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal testbed adapters, not the full MaskID contracts.
contract SourceCredentialRegistry {
    address public owner;
    mapping(bytes32 => bool) public issued;
    event Issued(bytes32 indexed credentialHash, address indexed issuer);
    constructor() { owner = msg.sender; }
    function issue(bytes32 credentialHash) external {
        require(msg.sender == owner, "issuer only");
        require(!issued[credentialHash], "already issued");
        issued[credentialHash] = true;
        emit Issued(credentialHash, msg.sender);
    }
}

// Explicit trusted-verifier boundary: this contract does NOT verify Groth16.
contract TargetAcceptanceRegistry {
    address public verifier;
    mapping(bytes32 => bool) public accepted;
    event Accepted(bytes32 indexed requestHash, bytes32 credentialHash, bytes32 sourceTx, bytes32 certificateHash);
    constructor() { verifier = msg.sender; }
    function accept(bytes32 requestHash, bytes32 credentialHash, bytes32 sourceTx, bytes32 certificateHash) external {
        require(msg.sender == verifier, "verifier only");
        require(!accepted[requestHash], "replay");
        accepted[requestHash] = true;
        emit Accepted(requestHash, credentialHash, sourceTx, certificateHash);
    }
}
