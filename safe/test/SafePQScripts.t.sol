// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./SafePQFixture.sol";
import {DeployNestedSafes} from "../script/DeployNestedSafes.s.sol";
import {PlanNestedMigration} from "../script/PlanNestedMigration.s.sol";
import {ExecPlannedTx} from "../script/ExecPlannedTx.s.sol";
import {ExecNestedTx} from "../script/ExecNestedTx.s.sol";
import {InspectSafe} from "../script/InspectSafe.s.sol";
import {PqOwnerDigest} from "../script/PqOwnerDigest.s.sol";

/// The scripts, run against the local Safe deployments (canonical addresses overridden through the environment).
/// One test function: the scripts read process-wide environment variables.
contract SafePQScriptsTest is SafePQFixture {
    function test_scripts_endToEnd() public {
        vm.setEnv("SAFE_SINGLETON_150", vm.toString(singleton));
        vm.setEnv("SAFE_SINGLETON_L2_150", vm.toString(singletonL2));
        vm.setEnv("FALLBACK_HANDLER_150", vm.toString(handler));
        vm.setEnv("SAFE_MIGRATION_150", vm.toString(migration));
        vm.setEnv("MULTI_SEND_CALL_ONLY_150", vm.toString(multiSend));
        vm.setEnv("SAFE_PROXY_FACTORY_150", vm.toString(address(proxyFactory)));
        vm.setEnv("LENS", vm.toString(address(lens)));
        address impl = address(pqFactory.IMPLEMENTATION());

        // existing 1.4.1 Safe: 4 EOAs, 3/4, one module
        uint256[] memory pks = _eoaKeys(4, 0xE0A0);
        ISafeExec root = _safe(singleton141, _addrs(pks), 3, handler141);
        vm.prank(address(root));
        root.enableModule(makeAddr("legacyModule"));
        PQHolder[] memory hs = _pqHolders(3, 31);

        // ---- DeployNestedSafes (the ECDSA side reuses 3 of the current owners)
        uint256[] memory ecdsaSide = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            ecdsaSide[i] = pks[i];
        }
        vm.setEnv("ECDSA_OWNERS", _csv(_addrs(ecdsaSide)));
        vm.setEnv("PQ_OWNERS", _csv(_pqAddrs(hs)));
        vm.setEnv("K", "2");
        vm.setEnv("PQ_IMPLEMENTATION", vm.toString(impl));
        vm.setEnv("SALT_NONCE", "777");
        (address sEcdsa, address sPq) = new DeployNestedSafes().run();
        vm.removeFile(string.concat("plans/31337-children-", vm.toString(sEcdsa), ".json"));

        // a 7702-delegated or non-clone PQ owner is refused before anything is broadcast
        vm.setEnv("PQ_OWNERS", _csv(_addrs(ecdsaSide)));
        DeployNestedSafes badDeploy = new DeployNestedSafes();
        vm.expectRevert();
        badDeploy.run();
        vm.setEnv("PQ_OWNERS", _csv(_pqAddrs(hs)));

        // ---- InspectSafe
        vm.setEnv("SAFE", vm.toString(address(root)));
        new InspectSafe().run();

        // ---- PqOwnerDigest on the children, before the root is reconfigured:
        // the digests do not depend on the root's owners, only on its transaction
        vm.setEnv("ROOT", vm.toString(address(root)));
        vm.setEnv("S_ECDSA", vm.toString(sEcdsa));
        vm.setEnv("S_PQ", vm.toString(sPq));
        vm.setEnv("TO", vm.toString(makeAddr("payee")));
        vm.setEnv("VALUE", "1000000000000000000");
        new PqOwnerDigest().run();

        // ---- PlanNestedMigration with dry run
        vm.setEnv("PLAN_OUT", "plans/test-31337-plan.json");
        vm.setEnv("SIMULATE", "true");
        uint256 snap = vm.snapshotState();
        new PlanNestedMigration().run();
        lens.requireNested(address(root), sEcdsa, sPq, 2, impl);
        vm.revertToState(snap);
        assertEq(root.VERSION(), "1.4.1");

        // ---- plan only, then execute both steps with owner signatures (raw hash and eth_sign flavours)
        vm.setEnv("SIMULATE", "false");
        string memory path = new PlanNestedMigration().run();
        string memory json = vm.readFile(path);
        vm.setEnv("PLAN", path);

        vm.setEnv("STEP", "migration");
        vm.setEnv("SIGNATURES", _mixedSigs(vm.parseJsonBytes32(json, ".migration.safeTxHash"), pks));
        new ExecPlannedTx().run();
        assertEq(root.VERSION(), "1.5.0");

        vm.setEnv("STEP", "reconfig");
        vm.setEnv("SIGNATURES", _mixedSigs(vm.parseJsonBytes32(json, ".reconfig.safeTxHash"), pks));
        new ExecPlannedTx().run();
        lens.requireNested(address(root), sEcdsa, sPq, 2, impl);

        // replaying a consumed step is refused (stale nonce)
        ExecPlannedTx replay = new ExecPlannedTx();
        vm.expectRevert();
        replay.run();

        vm.removeFile(path);

        // ---- ExecNestedTx: a plain transfer of the reconfigured root, signed on both sides
        address payee = makeAddr("payee");
        vm.deal(address(root), 5 ether);
        vm.setEnv("TO", vm.toString(payee));
        vm.setEnv("VALUE", "1000000000000000000");
        vm.setEnv("DATA", "0x");

        bytes32 safeTxHash = ISafeExec(address(root)).getTransactionHash(
            payee, 1 ether, "", 0, 0, 0, 0, address(0), address(0), root.nonce()
        );
        bytes32 ecdsaDigest = Sigs.safeMessageHash(sEcdsa, safeTxHash);
        vm.setEnv("ECDSA_SIGNERS", string.concat(vm.toString(vm.addr(pks[0])), ",", vm.toString(vm.addr(pks[2]))));
        // one raw, one eth_sign: the script detects the flavour by recovering
        vm.setEnv(
            "ECDSA_SIGNATURES",
            string.concat(
                vm.toString(_rsv(pks[0], ecdsaDigest)),
                ",",
                vm.toString(
                    _rsv(pks[2], keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ecdsaDigest)))
                )
            )
        );

        PQHolder[] memory signing = _pick(hs, 0, 2);
        string memory owners;
        string memory k1Sigs;
        string memory keys;
        string memory pqSigs;
        for (uint256 i = 0; i < signing.length; i++) {
            bytes32 d = Sigs.nestedOwnerDigest(sPq, address(signing[i].account), safeTxHash);
            string memory sep = i == 0 ? "" : ",";
            owners = string.concat(owners, sep, vm.toString(address(signing[i].account)));
            k1Sigs = string.concat(k1Sigs, sep, vm.toString(_rsv(signing[i].k1Pk, d)));
            keys = string.concat(keys, sep, vm.toString(signing[i].postQKeyRef));
            pqSigs = string.concat(pqSigs, sep, vm.toString(_mldsa65("sign", signing[i].seed, _hex32(d))));
        }
        vm.setEnv("PQ_OWNERS", owners);
        vm.setEnv("PQ_K1_SIGNATURES", k1Sigs);
        vm.setEnv("PQ_KEYS", keys);
        vm.setEnv("PQ_SIGNATURES", pqSigs);

        uint256 before = payee.balance;
        new ExecNestedTx().run();
        assertEq(payee.balance, before + 1 ether, "the nested transfer went through");
    }

    /// owner 3: raw hash; owner 0: eth_sign; owner 2: raw hash (unsorted on purpose)
    function _mixedSigs(bytes32 h, uint256[] memory pks) internal pure returns (string memory) {
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        return string.concat(
            vm.toString(_rsv(pks[3], h)), ",", vm.toString(_rsv(pks[0], ethSigned)), ",", vm.toString(_rsv(pks[2], h))
        );
    }

    function _csv(address[] memory a) internal pure returns (string memory s) {
        for (uint256 i = 0; i < a.length; i++) {
            s = i == 0 ? vm.toString(a[i]) : string.concat(s, ",", vm.toString(a[i]));
        }
    }
}
