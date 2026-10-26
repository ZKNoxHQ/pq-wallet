// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_PQAccount7702.sol
// Description: hybrid (pre-quantum AND post-quantum) account, usable both as an EIP-7702 delegate and
//              as an ERC-4337 account (minimal proxy deployed by ZKNOX_PQFactory7702).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/contracts/core/Helpers.sol";
import {Exec} from "account-abstraction/contracts/utils/Exec.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

/// @title ZKNOX_PQAccount7702
/// @notice A transaction is authorized when BOTH a pre-quantum signature (ECDSA k1 or r1) and a
///         post-quantum signature (ML-DSA-44 or Falcon-512) verify on the same digest.
///
///         Deployment model: one implementation per (pre-quantum, post-quantum) verifier pair, per chain.
///         - EIP-7702: an EOA delegates to the implementation, then calls `initialize` on itself.
///         - ERC-4337: `ZKNOX_PQFactory7702` deploys an ERC-1167 clone and initializes it atomically.
///         Everything shared lives in immutables (code); everything per account lives in an ERC-7201
///         namespaced storage slot, so the storage never collides with another delegate.
///
///         Keys are not stored: the account keeps `keccak256` of the verifier-normalized key (what
///         `ISigVerifier.setKey` returns: 20 bytes for a k1 address or an SSTORE2 pointer, 64 for r1),
///         and every signature carries the normalized keys, checked against the hashes. Two SLOAD per
///         validation whatever the size of the post-quantum key.
///
/// @dev    Signature encoding, for userOps, ERC-1271 and `executeWithHybridSig`:
///         abi.encode(bytes preQKey, bytes preQSig, bytes postQKey, bytes postQSig)
///
///         EIP-7702 caveat: the EOA's secp256k1 key remains a protocol-level authority. It can send
///         transactions that bypass this code and re-delegate at will. Under 7702 the post-quantum
///         signature is a second factor, not quantum resistance of the EOA. The clone model does not
///         have this caveat.
/// @custom:experimental Not audited, do not use in production.
contract ZKNOX_PQAccount7702 is BaseAccount, IERC1271, IERC165, IERC721Receiver, IERC1155Receiver {
    // ------------------------------------------------------------------ immutables (code, shared by all accounts)
    IEntryPoint private immutable ENTRY_POINT;
    ISigVerifier public immutable PRE_QUANTUM_VERIFIER;
    ISigVerifier public immutable POST_QUANTUM_VERIFIER;
    /// @notice the only address other than the account itself allowed to call `initialize` (ERC-4337 clones)
    address public immutable FACTORY;

    // ------------------------------------------------------------------ ERC-7201 storage
    /// @custom:storage-location erc7201:zknox.pqaccount.v1
    struct PQStorage {
        bytes32 preQKeyHash; // keccak256 of the normalized pre-quantum key
        bytes32 postQKeyHash; // keccak256 of the normalized post-quantum key
        uint256 pqNonce; // replay protection of `executeWithHybridSig` (independent of the EntryPoint nonces)
    }

    // keccak256(abi.encode(uint256(keccak256("zknox.pqaccount.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PQ_STORAGE_SLOT = 0xa1c9fb4003d093dfa2fe8a427dd689f47e37fcf22ffa0fca873be97f59ccf300;

    function _s() private pure returns (PQStorage storage $) {
        assembly {
            $.slot := PQ_STORAGE_SLOT
        }
    }

    // ------------------------------------------------------------------ EIP-712
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("ZKNOX_PQAccount7702");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant EXECUTE_TYPEHASH = keccak256("Execute(bytes32 callsHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant WRAPPED_TYPEHASH = keccak256("ZKNOXWrapped(bytes32 hash)");

    // ------------------------------------------------------------------ events / errors
    event PQAccountInitialized(bytes32 indexed preQKeyHash, bytes32 indexed postQKeyHash);
    event PreQuantumKeyRotated(bytes32 indexed oldKeyHash, bytes32 indexed newKeyHash);
    event PostQuantumKeyRotated(bytes32 indexed oldKeyHash, bytes32 indexed newKeyHash);

    error AlreadyInitialized();
    error NotAuthorized();
    error InvalidSignature();
    error Expired();

    constructor(
        IEntryPoint entryPoint_,
        ISigVerifier preQuantumVerifier,
        ISigVerifier postQuantumVerifier,
        address factory
    ) {
        ENTRY_POINT = entryPoint_;
        PRE_QUANTUM_VERIFIER = preQuantumVerifier;
        POST_QUANTUM_VERIFIER = postQuantumVerifier;
        FACTORY = factory;
    }

    // ------------------------------------------------------------------ initialization
    /// @notice Normalizes the raw keys through the verifiers (`setKey`: identity for k1/r1, SSTORE2 write of
    ///         the public key blob for ML-DSA and Falcon) and records their hashes.
    /// @dev    EIP-7702: call it on the EOA, from the EOA, in the type-4 transaction itself
    ///         (`to` = the EOA, msg.sender == address(this)): atomic with the delegation, not front-runnable.
    ///         ERC-4337: called by the factory right after the clone is created, in the same transaction.
    function initialize(bytes calldata preQuantumPubKey, bytes calldata postQuantumPubKey) external {
        _requireInitializer();
        bytes memory preQ = PRE_QUANTUM_VERIFIER.setKey(preQuantumPubKey);
        bytes memory postQ = POST_QUANTUM_VERIFIER.setKey(postQuantumPubKey);
        _initialize(keccak256(preQ), keccak256(postQ));
    }

    /// @notice Same as `initialize` but with keys already normalized (e.g. a post-quantum key blob already
    ///         written with `verifier.setKey` by anyone, on any previous transaction). No deployment cost here.
    function initializeWithKeyRefs(bytes calldata preQuantumKeyRef, bytes calldata postQuantumKeyRef) external {
        _requireInitializer();
        _initialize(keccak256(preQuantumKeyRef), keccak256(postQuantumKeyRef));
    }

    function _requireInitializer() internal view {
        if (msg.sender != address(this) && msg.sender != FACTORY) revert NotAuthorized();
    }

    function _initialize(bytes32 preQKeyHash, bytes32 postQKeyHash) internal {
        PQStorage storage $ = _s();
        if ($.postQKeyHash != 0) revert AlreadyInitialized();
        if (preQKeyHash == 0 || postQKeyHash == 0) revert InvalidSignature();
        $.preQKeyHash = preQKeyHash;
        $.postQKeyHash = postQKeyHash;
        emit PQAccountInitialized(preQKeyHash, postQKeyHash);
    }

    // ------------------------------------------------------------------ key rotation
    /// @dev Reachable through the EntryPoint (after the hybrid validation of the userOp) or by a self-call
    ///      (EOA transaction under EIP-7702, `execute` from a userOp, `executeWithHybridSig`).
    function setPreQuantumKey(bytes calldata newPubKey) external {
        _requireForExecute();
        PQStorage storage $ = _s();
        bytes32 h = keccak256(PRE_QUANTUM_VERIFIER.setKey(newPubKey));
        emit PreQuantumKeyRotated($.preQKeyHash, h);
        $.preQKeyHash = h;
    }

    function setPostQuantumKey(bytes calldata newPubKey) external {
        _requireForExecute();
        PQStorage storage $ = _s();
        bytes32 h = keccak256(POST_QUANTUM_VERIFIER.setKey(newPubKey));
        emit PostQuantumKeyRotated($.postQKeyHash, h);
        $.postQKeyHash = h;
    }

    // ------------------------------------------------------------------ ERC-4337
    function entryPoint() public view override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    function _requireForExecute() internal view override {
        if (msg.sender != address(this) && msg.sender != address(ENTRY_POINT)) revert NotAuthorized();
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        return _verifyHybrid(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /// @dev Both verifiers must return the magic value on the same digest, and both keys must match the
    ///      recorded hashes. Returns false instead of reverting so that a userOp with a bad signature is
    ///      reported as SIG_VALIDATION_FAILED (bundler simulation) rather than as a revert.
    ///      Both verifiers are always called, whatever the first one returns: bundlers estimate
    ///      `verificationGasLimit` with a stub signature (eth_estimateUserOperationGas ignores the
    ///      signature failure), so the gas consumed by a failing signature must be the gas of a
    ///      valid one. A stub is a real hybrid signature over any other digest: every structural
    ///      check passes, only the final comparison fails.
    function _verifyHybrid(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        PQStorage storage $ = _s();
        if ($.postQKeyHash == 0) return false;
        (bytes memory preQKey, bytes memory preQSig, bytes memory postQKey, bytes memory postQSig) =
            abi.decode(signature, (bytes, bytes, bytes, bytes));
        if (keccak256(preQKey) != $.preQKeyHash || keccak256(postQKey) != $.postQKeyHash) return false;
        bool preOk = PRE_QUANTUM_VERIFIER.verify(preQKey, digest, preQSig) == ISigVerifier.verify.selector;
        bool postOk = POST_QUANTUM_VERIFIER.verify(postQKey, digest, postQSig) == ISigVerifier.verify.selector;
        return preOk && postOk;
    }

    // ------------------------------------------------------------------ relayed execution without a bundler
    /// @notice Executes `calls` if the hybrid signature over (calls, nonce, deadline) is valid. Anyone can
    ///         submit it and pay the gas: this is the path when no bundler accepts a 1-2M gas validation.
    function executeWithHybridSig(Call[] calldata calls, uint256 deadline, bytes calldata signature) external payable {
        if (block.timestamp > deadline) revert Expired();
        PQStorage storage $ = _s();
        uint256 nonce = $.pqNonce++;
        bytes32 digest = _hashTypedData(keccak256(abi.encode(EXECUTE_TYPEHASH, _callsHash(calls), nonce, deadline)));
        if (!_verifyHybrid(digest, signature)) revert InvalidSignature();
        for (uint256 i = 0; i < calls.length; i++) {
            if (!Exec.call(calls[i].target, calls[i].value, calls[i].data, gasleft())) {
                Exec.revertWithReturnData();
            }
        }
    }

    /// @notice Digest to sign for `executeWithHybridSig` (wallet side helper).
    function hashExecute(Call[] calldata calls, uint256 nonce, uint256 deadline) external view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(EXECUTE_TYPEHASH, _callsHash(calls), nonce, deadline)));
    }

    function pqNonce() external view returns (uint256) {
        return _s().pqNonce;
    }

    function _callsHash(Call[] calldata calls) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            hashes[i] = keccak256(abi.encode(calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    // ------------------------------------------------------------------ ERC-1271
    /// @notice The dApp-provided hash is wrapped in this account's EIP-712 domain before verification, so a
    ///         signature is bound to (chainId, account) and cannot be replayed by another account sharing
    ///         the same key pair. Wallet side: sign `hashWrapped(hash)`, not `hash`.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        return _verifyHybrid(hashWrapped(hash), signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    function hashWrapped(bytes32 hash) public view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(WRAPPED_TYPEHASH, hash)));
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    // ------------------------------------------------------------------ views
    function keyHashes() external view returns (bytes32 preQKeyHash, bytes32 postQKeyHash) {
        PQStorage storage $ = _s();
        return ($.preQKeyHash, $.postQKeyHash);
    }

    function isInitialized() external view returns (bool) {
        return _s().postQKeyHash != 0;
    }

    // ------------------------------------------------------------------ receivers / introspection
    function supportsInterface(bytes4 id) public pure override returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IAccount).interfaceId || id == type(IERC1271).interfaceId
            || id == type(IERC721Receiver).interfaceId || id == type(IERC1155Receiver).interfaceId;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    receive() external payable {}
}
