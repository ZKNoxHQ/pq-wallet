// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_SafePQPlan.sol
// Description: Safe transactions that move an existing Safe (1.3.0 / 1.4.1 / 1.5.0) to a hybrid owner policy:
//              singleton migration, then one atomic MultiSendCallOnly batch of owner-management self-calls.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISafeOwnerManagement, ISafeMigration, IMultiSend} from "../interfaces/ISafeView.sol";
import {ZKNOX_SafePQLens} from "../ZKNOX_SafePQLens.sol";

library ZKNOX_SafePQPlan {
    uint8 internal constant CALL = 0;
    uint8 internal constant DELEGATECALL = 1;
    address internal constant SENTINEL = address(0x1);

    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
    }

    /// @param modules   enabled modules to disable, in `getModulesPaginated` order (each one's predecessor is then
    ///                  the sentinel when they are removed front to back)
    /// @param handler   fallback handler to set, 0 to leave it (the migration already sets the 1.5.0 one)
    /// @param lens      if non-zero, the batch ends with `lens.requireNested/requireSingle`: a configuration that
    ///                  does not satisfy the policy reverts the Safe transaction (safeTxGas = 0)
    struct Common {
        address multiSendCallOnly;
        address root;
        uint256 currentThreshold;
        address[] modules;
        bool clearGuard;
        address handler;
        address lens;
        uint256 k;
        address pqImplementation;
    }

    error OwnerAlreadyPresent(address owner);
    error NothingToAdd();

    /// @notice Singleton + fallback handler migration to 1.5.0 (DELEGATECALL to SafeMigration). L1/L2 must match
    ///         the current singleton flavour (SafeL2 emits the events L2 indexers rely on).
    function migrationTx(address safeMigration, bool l2) internal pure returns (SafeTx memory) {
        bytes4 selector = l2
            ? ISafeMigration.migrateL2WithFallbackHandler.selector
            : ISafeMigration.migrateWithFallbackHandler.selector;
        return SafeTx(safeMigration, 0, abi.encodeWithSelector(selector), DELEGATECALL);
    }

    /// @notice NESTED: the root keeps its address and ends owned by exactly {sEcdsa, sPq} with threshold 2.
    ///         `addOwnerWithThreshold` inserts at the head of the owner list, so after the two additions the list is
    ///         [sPq, sEcdsa, o1, o2, ...] and the predecessor of every previous owner removed front to back is sEcdsa.
    function nestedReconfigTx(Common memory c, address[] memory currentOwners, address sEcdsa, address sPq)
        internal
        pure
        returns (SafeTx memory)
    {
        for (uint256 i = 0; i < currentOwners.length; i++) {
            if (currentOwners[i] == sEcdsa || currentOwners[i] == sPq) {
                revert OwnerAlreadyPresent(currentOwners[i]);
            }
        }
        bytes memory txs = _preamble(c);
        txs = _append(
            txs, c.root, abi.encodeCall(ISafeOwnerManagement.addOwnerWithThreshold, (sEcdsa, c.currentThreshold))
        );
        txs =
            _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.addOwnerWithThreshold, (sPq, c.currentThreshold)));
        for (uint256 i = 0; i < currentOwners.length; i++) {
            txs = _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.removeOwner, (sEcdsa, currentOwners[i], 2)));
        }
        if (c.lens != address(0)) {
            txs = _append(
                txs,
                c.lens,
                abi.encodeCall(ZKNOX_SafePQLens.requireNested, (c.root, sEcdsa, sPq, c.k, c.pqImplementation))
            );
        }
        return _wrap(c.multiSendCallOnly, txs);
    }

    /// @notice SINGLE: the current owners stay (they must all be EOAs), PQ clones are added, threshold set to
    ///         `newThreshold` (>= nE + k and >= nP + k for the policy to hold).
    function singleReconfigTx(Common memory c, address[] memory pqOwners, uint256 newThreshold)
        internal
        pure
        returns (SafeTx memory)
    {
        if (pqOwners.length == 0) revert NothingToAdd();
        bytes memory txs = _preamble(c);
        for (uint256 i = 0; i < pqOwners.length; i++) {
            uint256 t = i + 1 == pqOwners.length ? newThreshold : c.currentThreshold;
            txs = _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.addOwnerWithThreshold, (pqOwners[i], t)));
        }
        if (c.lens != address(0)) {
            txs =
                _append(txs, c.lens, abi.encodeCall(ZKNOX_SafePQLens.requireSingle, (c.root, c.k, c.pqImplementation)));
        }
        return _wrap(c.multiSendCallOnly, txs);
    }

    function _preamble(Common memory c) private pure returns (bytes memory txs) {
        for (uint256 i = 0; i < c.modules.length; i++) {
            txs = _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.disableModule, (SENTINEL, c.modules[i])));
        }
        if (c.clearGuard) {
            txs = _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.setGuard, (address(0))));
        }
        if (c.handler != address(0)) {
            txs = _append(txs, c.root, abi.encodeCall(ISafeOwnerManagement.setFallbackHandler, (c.handler)));
        }
    }

    /// MultiSend packed encoding: operation (1) || to (20) || value (32) || data length (32) || data
    function _append(bytes memory txs, address to, bytes memory data) private pure returns (bytes memory) {
        return bytes.concat(txs, abi.encodePacked(CALL, to, uint256(0), uint256(data.length), data));
    }

    function _wrap(address multiSendCallOnly, bytes memory txs) private pure returns (SafeTx memory) {
        return SafeTx(multiSendCallOnly, 0, abi.encodeCall(IMultiSend.multiSend, (txs)), DELEGATECALL);
    }
}
