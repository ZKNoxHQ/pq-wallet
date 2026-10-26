// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ExecPlannedTx.s.sol
// Description: executes one step of a plan written by PlanNestedMigration with EOA owner signatures.
//              Each signature is either over the raw safeTxHash (v = 27/28) or an EIP-191 signature of the
//              32-byte hash as produced by `cast wallet sign --ledger <safeTxHash>` (eth_sign flow, v + 4);
//              the flavour is detected by recovering an owner. Signatures are sorted here.
//   PLAN=plans/1-0x....json STEP=migration SIGNATURES=0x..,0x..,0x.. \
//   forge script script/ExecPlannedTx.s.sol --rpc-url $RPC --ledger --sender $RELAYER --broadcast
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQSignatures as Sigs} from "../src/libraries/ZKNOX_SafePQSignatures.sol";
import {ISafeView, ISafeExecution} from "../src/interfaces/ISafeView.sol";

contract ExecPlannedTx is SafePQScriptBase {
    error UnknownSigner(uint256 index);
    error NotEnoughSignatures(uint256 got, uint256 threshold);
    error StalePlan(bytes32 planned, bytes32 current);

    function run() external {
        string memory json = vm.readFile(vm.envString("PLAN"));
        string memory step = string.concat(".", vm.envString("STEP"));
        require(vm.parseJsonBool(json, string.concat(step, ".needed")), "step not needed");
        address root = vm.parseJsonAddress(json, ".root");
        address to = vm.parseJsonAddress(json, string.concat(step, ".to"));
        uint256 value = vm.parseJsonUint(json, string.concat(step, ".value"));
        bytes memory data = vm.parseJsonBytes(json, string.concat(step, ".data"));
        uint8 operation = uint8(vm.parseJsonUint(json, string.concat(step, ".operation")));
        bytes32 planned = vm.parseJsonBytes32(json, string.concat(step, ".safeTxHash"));

        ISafeView r = ISafeView(root);
        bytes32 h = r.getTransactionHash(to, value, data, operation, 0, 0, 0, address(0), address(0), r.nonce());
        if (h != planned) revert StalePlan(planned, h);

        bytes memory packed = packEoaSignatures(root, h, vm.envBytes("SIGNATURES", ","));
        vm.startBroadcast();
        ISafeExecution(root)
            .execTransaction(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)), packed);
        vm.stopBroadcast();
        console.log("executed", vm.envString("STEP"), "on", root);
        console.log("version now", r.VERSION(), "nonce", r.nonce());
    }

    function packEoaSignatures(address root, bytes32 h, bytes[] memory raw) public view returns (bytes memory) {
        ISafeView r = ISafeView(root);
        address[] memory owners = r.getOwners();
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](raw.length);
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        for (uint256 i = 0; i < raw.length; i++) {
            require(raw[i].length == 65, "signature must be 65 bytes");
            (bytes32 rr, bytes32 ss, uint8 v) = _split(raw[i]);
            if (v < 27) v += 27;
            address a = ecrecover(h, v, rr, ss);
            if (_isOwner(owners, a)) {
                s[i] = Sigs.ecdsa(a, abi.encodePacked(rr, ss, v));
                continue;
            }
            a = ecrecover(ethSigned, v, rr, ss);
            if (!_isOwner(owners, a)) revert UnknownSigner(i);
            s[i] = Sigs.ecdsa(a, abi.encodePacked(rr, ss, v + 4));
        }
        if (raw.length < r.getThreshold()) revert NotEnoughSignatures(raw.length, r.getThreshold());
        return Sigs.pack(s);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 rr, bytes32 ss, uint8 v) {
        assembly {
            rr := mload(add(sig, 32))
            ss := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function _isOwner(address[] memory owners, address a) internal pure returns (bool) {
        if (a == address(0)) return false;
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == a) return true;
        }
        return false;
    }
}
