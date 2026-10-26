// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_PQSatellite7702.sol
// Description: EIP-7702 delegate for an EOA linked to a post-quantum vault (ZKNOX_PQAccount7702 clone).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {ZKNOX_PQAccount7702} from "./ZKNOX_PQAccount7702.sol";

/// @title ZKNOX_PQSatellite7702
/// @notice The EOA side of a two-pot setup. The EOA delegates to this contract and links it to a vault
///         (a ZKNOX_PQAccount7702 clone, no EOA key, hybrid pre-quantum AND post-quantum authorization).
///
///         - Funds at the EOA address are the NON-post-quantum pot: the EOA's secp256k1 key keeps its
///           protocol-level authority and can always spend them. This contract does not pretend otherwise:
///           its own userOps are authorized by that key alone (like Simple7702Account).
///         - Funds in the vault are the post-quantum pot.
///         - `sweep` moves ETH (above a gas reserve) and listed tokens from the EOA to the vault, callable
///           by anyone: incoming funds on the public address reach the post-quantum pot without a signature.
///         - The vault may `execute` through this contract (`msg.sender == vault`), so a single hybrid
///           signature can act with `msg.sender == EOA` when a position is attached to the EOA address.
///         - ERC-1271 on the EOA address is relayed to the vault: signatures in the name of the EOA require
///           the post-quantum factor (contracts calling `ecrecover` directly still accept the EOA key).
///
///         One deployment per chain; per-EOA state lives in an ERC-7201 slot (`zknox.pqsatellite.v1`).
/// @custom:experimental Not audited, do not use in production.
contract ZKNOX_PQSatellite7702 is BaseAccount, IERC1271, IERC165, IERC721Receiver, IERC1155Receiver {
    using SafeERC20 for IERC20;

    IEntryPoint private immutable ENTRY_POINT;

    /// @custom:storage-location erc7201:zknox.pqsatellite.v1
    struct SatelliteStorage {
        address vault; // ZKNOX_PQAccount7702 clone receiving sweeps and allowed to execute through this account
        uint256 gasReserve; // ETH kept on the EOA by `sweep`, for its own gas
    }

    // keccak256(abi.encode(uint256(keccak256("zknox.pqsatellite.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SATELLITE_STORAGE_SLOT =
        0x7dc0ab30d2f010c5a0e75ae2fda8bbc28fbe8f603021c67276e67f72622c3f00;

    function _s() private pure returns (SatelliteStorage storage $) {
        assembly {
            $.slot := SATELLITE_STORAGE_SLOT
        }
    }

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("ZKNOX_PQSatellite7702");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant WRAPPED_TYPEHASH = keccak256("ZKNOXSatelliteWrapped(bytes32 hash)");

    event SatelliteInitialized(address indexed vault, uint256 gasReserve);
    event VaultChanged(address indexed oldVault, address indexed newVault);
    event GasReserveChanged(uint256 oldReserve, uint256 newReserve);
    event Swept(address indexed vault, uint256 eth, address[] tokens);

    error AlreadyInitialized();
    error NotInitialized();
    error NotAuthorized();
    error ZeroVault();

    constructor(IEntryPoint entryPoint_) {
        ENTRY_POINT = entryPoint_;
    }

    // ------------------------------------------------------------------ initialization / settings
    /// @notice Links the EOA to its vault. Call it on the EOA, from the EOA, in the type-4 transaction
    ///         itself (`to` = the EOA): atomic with the delegation, not front-runnable.
    function initialize(address vault_, uint256 gasReserve_) external {
        if (msg.sender != address(this)) revert NotAuthorized();
        SatelliteStorage storage $ = _s();
        if ($.vault != address(0)) revert AlreadyInitialized();
        if (vault_ == address(0)) revert ZeroVault();
        $.vault = vault_;
        $.gasReserve = gasReserve_;
        emit SatelliteInitialized(vault_, gasReserve_);
    }

    /// @dev Self (EOA key), EntryPoint (after ECDSA validation) or the vault (hybrid signature).
    function setVault(address newVault) external {
        _requireForExecute();
        if (newVault == address(0)) revert ZeroVault();
        SatelliteStorage storage $ = _s();
        emit VaultChanged($.vault, newVault);
        $.vault = newVault;
    }

    function setGasReserve(uint256 newReserve) external {
        _requireForExecute();
        SatelliteStorage storage $ = _s();
        emit GasReserveChanged($.gasReserve, newReserve);
        $.gasReserve = newReserve;
    }

    // ------------------------------------------------------------------ sweep to the post-quantum pot
    /// @notice Sends every wei above `gasReserve` and the full balance of each listed token to the vault.
    ///         Callable by anyone: the destination is fixed, only the timing is the caller's.
    function sweep(address[] calldata tokens) external {
        SatelliteStorage storage $ = _s();
        address vault_ = $.vault;
        if (vault_ == address(0)) revert NotInitialized();

        uint256 eth = 0;
        uint256 balance = address(this).balance;
        if (balance > $.gasReserve) {
            eth = balance - $.gasReserve;
            (bool ok,) = vault_.call{value: eth}("");
            require(ok, "sweep: eth transfer failed");
        }
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = IERC20(tokens[i]);
            uint256 amount = token.balanceOf(address(this));
            if (amount > 0) token.safeTransfer(vault_, amount);
        }
        emit Swept(vault_, eth, tokens);
    }

    // ------------------------------------------------------------------ ERC-4337 (EOA key only, non-post-quantum pot)
    function entryPoint() public view override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    function _requireForExecute() internal view override {
        if (msg.sender != address(this) && msg.sender != address(ENTRY_POINT) && msg.sender != _s().vault) {
            revert NotAuthorized();
        }
    }

    /// @dev userOp.signature = r || s || v of the EOA key over userOpHash (EntryPoint v0.8 hash, already EIP-712).
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        (address signer,,) = ECDSA.tryRecover(userOpHash, userOp.signature);
        return signer == address(this) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    // ------------------------------------------------------------------ ERC-1271, relayed to the vault
    /// @notice A signature in the name of the EOA is a hybrid signature, checked by the vault, over
    ///         `hashWrapped(hash)`. The hash is first bound to this EOA (chainId, address), then the vault
    ///         binds it to itself: a signature valid here is not valid as a direct vault signature and
    ///         conversely.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        address vault_ = _s().vault;
        if (vault_ == address(0)) return bytes4(0xffffffff);
        return IERC1271(vault_).isValidSignature(_wrap(hash), signature);
    }

    /// @notice Digest to sign (with the vault's keys) for an ERC-1271 signature in the name of the EOA.
    function hashWrapped(bytes32 hash) external view returns (bytes32) {
        return ZKNOX_PQAccount7702(payable(_s().vault)).hashWrapped(_wrap(hash));
    }

    function _wrap(bytes32 hash) internal view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
        return keccak256(abi.encodePacked("\x19\x01", domain, keccak256(abi.encode(WRAPPED_TYPEHASH, hash))));
    }

    // ------------------------------------------------------------------ views
    function vault() external view returns (address) {
        return _s().vault;
    }

    function gasReserve() external view returns (uint256) {
        return _s().gasReserve;
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
