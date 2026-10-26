// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ExecNestedTx.s.sol
// Description: executes a transaction of a NESTED root from the signatures the two child Safes collected,
//              assembling the three layers (root, children, post-quantum clones) in one send.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQSignatures as Sigs} from "../src/libraries/ZKNOX_SafePQSignatures.sol";
import {ISafeView, ISafeExecution} from "../src/interfaces/ISafeView.sol";

/// Sends one `execTransaction` on the root with a full hybrid signature set. It is the counterpart of
/// `PqOwnerDigest`: that script prints what each signer is handed, this one takes the answers back.
///
/// Three layers, assembled here so no one has to concatenate Safe signature blobs by hand:
///   - the EOA owners of S_ecdsa signed `safeMessageHash(S_ecdsa, safeTxHash)`, raw or EIP-191;
///   - each post-quantum owner of S_pq returned a k1 signature and an ML-DSA-65 signature over
///     `nestedOwnerDigest(S_pq, owner, safeTxHash)`, with the expanded key it signed with;
///   - the two child signatures become the root's own two contract signatures.
///
/// Nothing goes through the Safe Transaction Service: the transaction is sent to the RPC directly, which
/// is what a ~85 kB signature needs. The relayer pays the gas and authorizes nothing.
///
///   ROOT=0x... S_ECDSA=0x... S_PQ=0x... TO=0x... [VALUE=0] [DATA=0x] [OPERATION=0]
///   ECDSA_SIGNERS=0x..,0x..               # the EOAs that signed, in any order
///   ECDSA_SIGNATURES=0x..,0x..            # their 65-byte signatures, same order
///   PQ_OWNERS=0x..,0x..                   # the clones that signed, in any order
///   PQ_K1_SIGNATURES=0x..,0x..            # their 65-byte k1 signatures, same order
///   PQ_KEYS=0x..,0x..                     # their expanded ML-DSA-65 keys (38,112 bytes each)
///   PQ_SIGNATURES=0x..,0x..               # their 3,309-byte ML-DSA-65 signatures, same order
///   forge script script/ExecNestedTx.s.sol --rpc-url $RPC --ledger --sender $RELAYER --broadcast
///
/// DRY_RUN=true stops after printing the assembled signature and its size.
contract ExecNestedTx is SafePQScriptBase {
    error CountMismatch(string what, uint256 a, uint256 b);
    error NotEnoughSignatures(string side, uint256 got, uint256 threshold);
    error UnknownEcdsaSigner(address claimed, uint256 index);
    error BadLength(string what, uint256 index, uint256 got, uint256 expected);

    uint256 constant ML_DSA_65_SIGNATURE_BYTES = 3309;
    uint256 constant ML_DSA_65_KEY_BYTES = 38112;

    function run() external {
        address root = vm.envAddress("ROOT");
        address sEcdsa = vm.envAddress("S_ECDSA");
        address sPq = vm.envAddress("S_PQ");

        ISafeView r = ISafeView(root);
        address to = vm.envAddress("TO");
        uint256 value = vm.envOr("VALUE", uint256(0));
        bytes memory data = vm.envOr("DATA", bytes(""));
        uint8 operation = uint8(vm.envOr("OPERATION", uint256(0)));
        bytes32 safeTxHash =
            r.getTransactionHash(to, value, data, operation, 0, 0, 0, address(0), address(0), r.nonce());
        console.log("safeTxHash    ", vm.toString(safeTxHash));

        bytes memory ecdsaSide = _ecdsaChildSignature(sEcdsa, safeTxHash);
        bytes memory pqSide = _pqChildSignature(sPq, safeTxHash);

        Sigs.OwnerSig[] memory rootSigs = new Sigs.OwnerSig[](2);
        rootSigs[0] = Sigs.contractSig(sEcdsa, ecdsaSide);
        rootSigs[1] = Sigs.contractSig(sPq, pqSide);
        bytes memory signatures = Sigs.pack(rootSigs);

        console.log("S_ecdsa signature bytes", ecdsaSide.length);
        console.log("S_pq signature bytes   ", pqSide.length);
        console.log("root signature bytes   ", signatures.length);

        if (vm.envOr("DRY_RUN", false)) {
            console.log("DRY_RUN: nothing sent");
            return;
        }

        vm.startBroadcast();
        ISafeExecution(root).execTransaction(
            to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), signatures
        );
        vm.stopBroadcast();
        console.log("executed, root nonce now", r.nonce());
    }

    /// The EOA side: its owners signed the SafeMessage hash of S_ecdsa, raw or through eth_sign.
    function _ecdsaChildSignature(address sEcdsa, bytes32 safeTxHash) internal view returns (bytes memory) {
        address[] memory signers = vm.envAddress("ECDSA_SIGNERS", ",");
        bytes[] memory raw = vm.envBytes("ECDSA_SIGNATURES", ",");
        if (signers.length != raw.length) {
            revert CountMismatch("ECDSA_SIGNERS / ECDSA_SIGNATURES", signers.length, raw.length);
        }
        uint256 threshold = ISafeView(sEcdsa).getThreshold();
        if (signers.length < threshold) revert NotEnoughSignatures("S_ecdsa", signers.length, threshold);

        bytes32 h = Sigs.safeMessageHash(sEcdsa, safeTxHash);
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            if (raw[i].length != 65) revert BadLength("ECDSA signature", i, raw[i].length, 65);
            (bytes32 rr, bytes32 ss, uint8 v) = _split(raw[i]);
            if (v < 27) v += 27;
            // the signer tells us who it is; recovering says which of the two digests it signed
            if (ecrecover(h, v, rr, ss) == signers[i]) {
                s[i] = Sigs.ecdsa(signers[i], abi.encodePacked(rr, ss, v));
            } else if (ecrecover(ethSigned, v, rr, ss) == signers[i]) {
                s[i] = Sigs.ecdsa(signers[i], abi.encodePacked(rr, ss, v + 4));
            } else {
                revert UnknownEcdsaSigner(signers[i], i);
            }
        }
        return Sigs.pack(s);
    }

    /// The post-quantum side: each clone returned two signatures over its own wrapped digest.
    function _pqChildSignature(address sPq, bytes32 safeTxHash) internal view returns (bytes memory) {
        address[] memory owners = vm.envAddress("PQ_OWNERS", ",");
        bytes[] memory k1 = vm.envBytes("PQ_K1_SIGNATURES", ",");
        bytes[] memory keys = vm.envBytes("PQ_KEYS", ",");
        bytes[] memory pq = vm.envBytes("PQ_SIGNATURES", ",");
        if (owners.length != k1.length) revert CountMismatch("PQ_OWNERS / PQ_K1_SIGNATURES", owners.length, k1.length);
        if (owners.length != keys.length) revert CountMismatch("PQ_OWNERS / PQ_KEYS", owners.length, keys.length);
        if (owners.length != pq.length) revert CountMismatch("PQ_OWNERS / PQ_SIGNATURES", owners.length, pq.length);
        uint256 threshold = ISafeView(sPq).getThreshold();
        if (owners.length < threshold) revert NotEnoughSignatures("S_pq", owners.length, threshold);

        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](owners.length);
        for (uint256 i = 0; i < owners.length; i++) {
            if (k1[i].length != 65) revert BadLength("k1 signature", i, k1[i].length, 65);
            if (keys[i].length != ML_DSA_65_KEY_BYTES) {
                revert BadLength("expanded key", i, keys[i].length, ML_DSA_65_KEY_BYTES);
            }
            if (pq[i].length != ML_DSA_65_SIGNATURE_BYTES) {
                revert BadLength("ML-DSA-65 signature", i, pq[i].length, ML_DSA_65_SIGNATURE_BYTES);
            }
            // the pre-quantum key is the k1 address, which the account stores as 20 bytes
            bytes32 digest = Sigs.nestedOwnerDigest(sPq, owners[i], safeTxHash);
            (bytes32 rr, bytes32 ss, uint8 v) = _split(k1[i]);
            if (v < 27) v += 27;
            address k1Signer = ecrecover(digest, v, rr, ss);
            console.log("  owner", owners[i], "k1 signer", k1Signer);
            s[i] = Sigs.contractSig(
                owners[i],
                Sigs.hybridPayload(abi.encodePacked(k1Signer), abi.encodePacked(rr, ss, v), keys[i], pq[i])
            );
        }
        return Sigs.pack(s);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 rr, bytes32 ss, uint8 v) {
        assembly {
            rr := mload(add(sig, 32))
            ss := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
