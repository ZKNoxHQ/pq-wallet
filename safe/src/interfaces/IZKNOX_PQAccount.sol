// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: IZKNOX_PQAccount.sol
// Description: the part of ZKNOX_PQAccount7702 (../contracts) this package relies on.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IZKNOX_PQAccount {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    function hashWrapped(bytes32 hash) external view returns (bytes32);
    function isInitialized() external view returns (bool);
    function keyHashes() external view returns (bytes32 preQKeyHash, bytes32 postQKeyHash);
}
