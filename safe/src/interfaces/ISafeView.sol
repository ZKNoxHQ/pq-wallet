// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ISafeView.sol
// Description: read and owner-management subset of Safe 1.3.0 / 1.4.1 / 1.5.0 used by this package.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISafeView {
    function VERSION() external view returns (string memory);
    function nonce() external view returns (uint256);
    function domainSeparator() external view returns (bytes32);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce_
    ) external view returns (bytes32);
}

interface ISafeExecution {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);
    function approveHash(bytes32 hashToApprove) external;
}

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

interface ISafeSetup {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeOwnerManagement {
    function addOwnerWithThreshold(address owner, uint256 threshold) external;
    function removeOwner(address prevOwner, address owner, uint256 threshold) external;
    function disableModule(address prevModule, address module) external;
    function setGuard(address guard) external;
    function setFallbackHandler(address handler) external;
}

interface ISafeMigration {
    function migrateWithFallbackHandler() external;
    function migrateL2WithFallbackHandler() external;
}

interface IMultiSend {
    function multiSend(bytes memory transactions) external payable;
}
