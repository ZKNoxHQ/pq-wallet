// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: PqOwnerDigest.s.sol
// Description: the 32 bytes a post-quantum owner has to sign for a transaction of a NESTED root, and the
//              ERC-1271 payload to assemble once both halves are signed.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQSignatures as Sigs} from "../src/libraries/ZKNOX_SafePQSignatures.sol";
import {ISafeView} from "../src/interfaces/ISafeView.sol";
import {IZKNOX_PQAccount} from "../src/interfaces/IZKNOX_PQAccount.sol";

/// Prints what each signer is handed for one transaction of the root Safe:
/// the root safeTxHash, the digest the EOA owners of S_ecdsa sign, and the
/// digest every post-quantum owner of S_pq signs with both of its keys.
///
/// The post-quantum digest is the whole chain, root safeTxHash -> SafeMessage
/// of S_pq -> EIP-712 wrap of the clone, so a hardware signer needs that one
/// value and nothing else: the ECML-Signer Ledger app takes it through
/// HYBRID_SIGN_HASH, and the k1 half is signed over the same bytes.
///
///   ROOT=0x... S_ECDSA=0x... S_PQ=0x... TO=0x... [VALUE=0] [DATA=0x] [OPERATION=0] [NONCE=<root nonce>]
///   forge script script/PqOwnerDigest.s.sol --rpc-url $RPC
///
/// PQ_OWNERS=0x..,0x.. restricts the listing to those clones; by default every
/// owner of S_pq is listed.
contract PqOwnerDigest is SafePQScriptBase {
    function run() external view {
        address root = vm.envAddress("ROOT");
        address sEcdsa = vm.envAddress("S_ECDSA");
        address sPq = vm.envAddress("S_PQ");

        ISafeView r = ISafeView(root);
        uint256 nonce = vm.envOr("NONCE", r.nonce());
        address to = vm.envAddress("TO");
        uint256 value = vm.envOr("VALUE", uint256(0));
        bytes memory data = vm.envOr("DATA", bytes(""));
        uint8 operation = uint8(vm.envOr("OPERATION", uint256(0)));

        bytes32 safeTxHash =
            r.getTransactionHash(to, value, data, operation, 0, 0, 0, address(0), address(0), nonce);

        console.log("root          ", root);
        console.log("nonce         ", nonce);
        console.log("to / value    ", to, value);
        console.log("safeTxHash    ", vm.toString(safeTxHash));
        console.log("");
        console.log("S_ecdsa       ", sEcdsa, "threshold", ISafeView(sEcdsa).getThreshold());
        console.log("  its EOA owners sign", vm.toString(Sigs.safeMessageHash(sEcdsa, safeTxHash)));
        console.log("");
        console.log("S_pq          ", sPq, "threshold", ISafeView(sPq).getThreshold());

        address[] memory owners = vm.envOr("PQ_OWNERS", ",", ISafeView(sPq).getOwners());
        for (uint256 i = 0; i < owners.length; i++) {
            bytes32 toSign = Sigs.nestedOwnerDigest(sPq, owners[i], safeTxHash);
            console.log("  owner", owners[i]);
            console.log("    signs (k1 and ML-DSA-65)", vm.toString(toSign));
            if (!IZKNOX_PQAccount(owners[i]).isInitialized()) {
                console.log("    WARNING: this account is not initialized");
            }
        }
        console.log("");
        console.log("Each post-quantum owner returns two signatures over its own digest. The ERC-1271");
        console.log("payload is abi.encode(preQKey, preQSig, postQKey, postQSig), where postQKey is the");
        console.log("38,112-byte expanded ML-DSA-65 key; ZKNOX_SafePQSignatures.pack orders them for Safe.");
    }
}
