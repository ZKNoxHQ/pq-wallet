// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_PQFactory7702.sol
// Description: deploys the ZKNOX_PQAccount7702 implementation (the EIP-7702 delegate) and, for the
//              ERC-4337 path, deterministic ERC-1167 clones of it.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {ZKNOX_PQAccount7702} from "./ZKNOX_PQAccount7702.sol";

/// @title ZKNOX_PQFactory7702
/// @notice One factory per (pre-quantum, post-quantum) verifier pair. The factory deploys the
///         implementation itself so that `FACTORY` is known to it: EOAs delegate to `IMPLEMENTATION`
///         (EIP-7702), the factory creates clones for accounts without an EOA (ERC-4337).
/// @dev    Deploy the factory with CREATE2 from the same deployer on every chain to get the same
///         `IMPLEMENTATION` address everywhere (a chainId 0 EIP-7702 authorization is valid on all chains).
contract ZKNOX_PQFactory7702 {
    ZKNOX_PQAccount7702 public immutable IMPLEMENTATION;
    string public VERSION;

    event AccountCreated(address indexed account, bytes32 indexed preQKeyHash, bytes32 indexed postQKeyHash);

    constructor(
        IEntryPoint entryPoint,
        ISigVerifier preQuantumVerifier,
        ISigVerifier postQuantumVerifier,
        string memory version
    ) {
        IMPLEMENTATION = new ZKNOX_PQAccount7702(entryPoint, preQuantumVerifier, postQuantumVerifier, address(this));
        VERSION = version;
    }

    /// @notice Creates (or returns) the ERC-4337 account for these raw keys. Clone creation and `initialize`
    ///         happen in the same call, so no one can initialize the account with other keys.
    function createAccount(bytes calldata preQuantumPubKey, bytes calldata postQuantumPubKey, uint256 salt)
        external
        returns (ZKNOX_PQAccount7702 account)
    {
        bytes32 s = _salt(preQuantumPubKey, postQuantumPubKey, salt);
        address predicted = Clones.predictDeterministicAddress(address(IMPLEMENTATION), s, address(this));
        if (predicted.code.length > 0) {
            return ZKNOX_PQAccount7702(payable(predicted));
        }
        account = ZKNOX_PQAccount7702(payable(Clones.cloneDeterministic(address(IMPLEMENTATION), s)));
        account.initialize(preQuantumPubKey, postQuantumPubKey);
        (bytes32 preQ, bytes32 postQ) = account.keyHashes();
        emit AccountCreated(address(account), preQ, postQ);
    }

    /// @notice Same as `createAccount` with keys already normalized (e.g. a post-quantum key blob written
    ///         beforehand with `verifier.setKey`, by anyone): no key-blob deployment inside this call.
    ///         The salt is computed on the references, so `getAddress` must be called with the same references.
    function createAccountWithKeyRefs(bytes calldata preQuantumKeyRef, bytes calldata postQuantumKeyRef, uint256 salt)
        external
        returns (ZKNOX_PQAccount7702 account)
    {
        bytes32 s = _salt(preQuantumKeyRef, postQuantumKeyRef, salt);
        address predicted = Clones.predictDeterministicAddress(address(IMPLEMENTATION), s, address(this));
        if (predicted.code.length > 0) {
            return ZKNOX_PQAccount7702(payable(predicted));
        }
        account = ZKNOX_PQAccount7702(payable(Clones.cloneDeterministic(address(IMPLEMENTATION), s)));
        account.initializeWithKeyRefs(preQuantumKeyRef, postQuantumKeyRef);
        (bytes32 preQ, bytes32 postQ) = account.keyHashes();
        emit AccountCreated(address(account), preQ, postQ);
    }

    function getAddress(bytes calldata preQuantumPubKey, bytes calldata postQuantumPubKey, uint256 salt)
        external
        view
        returns (address)
    {
        return Clones.predictDeterministicAddress(
            address(IMPLEMENTATION), _salt(preQuantumPubKey, postQuantumPubKey, salt), address(this)
        );
    }

    function _salt(bytes calldata preQ, bytes calldata postQ, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(preQ), keccak256(postQ), salt));
    }
}
