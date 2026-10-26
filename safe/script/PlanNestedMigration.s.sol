// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: PlanNestedMigration.s.sol
// Description: builds the Safe transactions that move ROOT (1.3.0 / 1.4.1 / 1.5.0) to the NESTED policy
//              {S_ecdsa, S_pq}, writes them with their SafeTx hashes to plans/<chainId>-<root>.json, and dry-runs
//              them on the RPC state (owners approve through vm.prank, nothing is broadcast).
//   ROOT=0x... S_ECDSA=0x... S_PQ=0x... K=2 PQ_IMPLEMENTATION=0x... [LENS=0x...] [DISABLE_MODULES=true]
//   [CLEAR_GUARD=false] [SIMULATE=true] forge script script/PlanNestedMigration.s.sol --rpc-url $RPC
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Script.sol";
import {SafePQScriptBase} from "./SafePQScriptBase.sol";
import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ZKNOX_SafePQPlan as Plan} from "../src/libraries/ZKNOX_SafePQPlan.sol";
import {ZKNOX_SafePQSignatures as Sigs} from "../src/libraries/ZKNOX_SafePQSignatures.sol";
import {ZKNOX_SafeDeployments as D} from "../src/libraries/ZKNOX_SafeDeployments.sol";
import {ISafeView, ISafeExecution} from "../src/interfaces/ISafeView.sol";

contract PlanNestedMigration is SafePQScriptBase {
    struct Planned {
        bool needed;
        Plan.SafeTx t;
        uint256 nonce;
        bytes32 safeTxHash;
    }

    function run() external returns (string memory path) {
        address root = vm.envAddress("ROOT");
        address sEcdsa = vm.envAddress("S_ECDSA");
        address sPq = vm.envAddress("S_PQ");
        uint256 k = vm.envUint("K");
        address impl = vm.envAddress("PQ_IMPLEMENTATION");
        address lensAddr = vm.envOr("LENS", address(0));
        if (lensAddr.code.length == 0) lensAddr = address(0);
        ZKNOX_SafePQLens lens = lensForReading();
        ISafeView r = ISafeView(root);

        requireCode(migration150(), "SafeMigration 1.5.0");
        requireCode(multiSend150(), "MultiSendCallOnly 1.5.0");

        // ---- current state
        string memory version = r.VERSION();
        bool needsMigration = !versionIs(root, "1.5.0");
        require(!needsMigration || versionIs(root, "1.4.1") || versionIs(root, "1.3.0"), "unsupported Safe version");
        address singleton = lens.singletonOf(root);
        bool l2 = vm.envOr("ROOT_L2", D.isKnownL2Singleton(singleton) || singleton == singletonL2150());
        (address[] memory modules,) = r.getModulesPaginated(SENTINEL, 50);
        bool disableModules = vm.envOr("DISABLE_MODULES", true);
        bool clearGuard = vm.envOr("CLEAR_GUARD", false);
        address guard = guardOf(root);
        if (modules.length > 0 && !disableModules) console.log("WARNING: modules kept, the lens check will fail");
        if (guard != address(0) && !clearGuard) console.log("NOTE: guard kept:", guard);

        // ---- plan
        uint256 n0 = r.nonce();
        Planned memory m;
        m.needed = needsMigration;
        if (needsMigration) {
            m.t = Plan.migrationTx(migration150(), l2);
            m.nonce = n0;
            m.safeTxHash = _hash(r, m.t, m.nonce);
        }
        Plan.Common memory c = Plan.Common({
            multiSendCallOnly: multiSend150(),
            root: root,
            currentThreshold: r.getThreshold(),
            modules: disableModules ? modules : new address[](0),
            clearGuard: clearGuard && guard != address(0),
            handler: !needsMigration && lens.fallbackHandlerOf(root) != handler150() ? handler150() : address(0),
            lens: lensAddr,
            k: k,
            pqImplementation: impl
        });
        Planned memory rc;
        rc.needed = true;
        rc.t = Plan.nestedReconfigTx(c, r.getOwners(), sEcdsa, sPq);
        rc.nonce = n0 + (needsMigration ? 1 : 0);
        rc.safeTxHash = _hash(r, rc.t, rc.nonce);

        path =
            vm.envOr("PLAN_OUT", string.concat("plans/", vm.toString(block.chainid), "-", vm.toString(root), ".json"));
        _write(path, root, version, sEcdsa, sPq, k, impl, m, rc);
        console.log("version       ", version, l2 ? "(L2)" : "(L1)");
        console.log("owners/thresh.", r.getOwners().length, r.getThreshold());
        if (needsMigration) console.log("migration     ", vm.toString(m.safeTxHash), "nonce", m.nonce);
        console.log("reconfig      ", vm.toString(rc.safeTxHash), "nonce", rc.nonce);
        console.log("lens in batch ", lensAddr == address(0) ? "no (LENS not deployed)" : "yes");
        console.log("plan written  ", path);

        // ---- dry run on the fork state
        if (vm.envOr("SIMULATE", true)) {
            if (needsMigration) _simulate(root, m.t);
            require(_hash(r, rc.t, r.nonce()) == rc.safeTxHash, "reconfig hash changed after migration");
            _simulate(root, rc.t);
            uint256 v = lens.nestedViolations(root, sEcdsa, sPq, k, impl);
            console.log("simulation OK, version", r.VERSION(), "lens violations", v);
            require(v == 0, "policy violated after simulation");
        }
    }

    function _hash(ISafeView r, Plan.SafeTx memory t, uint256 nonce_) internal view returns (bytes32) {
        return r.getTransactionHash(t.to, t.value, t.data, t.operation, 0, 0, 0, address(0), address(0), nonce_);
    }

    /// The first `threshold` owners approve the hash (vm.prank), then an arbitrary relayer executes.
    function _simulate(address root, Plan.SafeTx memory t) internal {
        ISafeView r = ISafeView(root);
        bytes32 h = _hash(r, t, r.nonce());
        address[] memory owners = r.getOwners();
        uint256 threshold = r.getThreshold();
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            vm.prank(owners[i]);
            ISafeExecution(root).approveHash(h);
            s[i] = Sigs.approved(owners[i]);
        }
        vm.prank(address(0xdead));
        ISafeExecution(root)
            .execTransaction(t.to, t.value, t.data, t.operation, 0, 0, 0, address(0), payable(address(0)), Sigs.pack(s));
    }

    function _write(
        string memory path,
        address root,
        string memory version,
        address sEcdsa,
        address sPq,
        uint256 k,
        address impl,
        Planned memory m,
        Planned memory rc
    ) internal {
        string memory o = "plan";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "root", root);
        vm.serializeString(o, "version", version);
        vm.serializeAddress(o, "sEcdsa", sEcdsa);
        vm.serializeAddress(o, "sPq", sPq);
        vm.serializeUint(o, "k", k);
        vm.serializeAddress(o, "pqImplementation", impl);
        vm.serializeString(o, "migration", _txJson("migration", m));
        string memory json = vm.serializeString(o, "reconfig", _txJson("reconfig", rc));
        vm.writeJson(json, path);
    }

    function _txJson(string memory key, Planned memory p) internal returns (string memory) {
        vm.serializeBool(key, "needed", p.needed);
        vm.serializeAddress(key, "to", p.t.to);
        vm.serializeUint(key, "value", p.t.value);
        vm.serializeBytes(key, "data", p.t.data);
        vm.serializeUint(key, "operation", p.t.operation);
        vm.serializeUint(key, "nonce", p.nonce);
        return vm.serializeBytes32(key, "safeTxHash", p.safeTxHash);
    }
}
