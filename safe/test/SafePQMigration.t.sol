// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import "./SafePQFixture.sol";

/// Existing Safe 1.4.1 (4 EOAs, 3/4, 1.4.1 handler, one module) moved in place to the NESTED policy:
/// tx 1 migrates to 1.5.0, tx 2 is the atomic reconfiguration ending with the lens check.
contract SafePQMigrationTest is SafePQFixture {
    uint256 constant K = 2;
    uint256[] ownerPks;
    PQHolder[] holders;
    ISafeExec root;
    ISafeExec sEcdsa;
    ISafeExec sPq;
    address module = makeAddr("legacyModule");
    address impl;

    function setUp() public override {
        super.setUp();
        impl = address(pqFactory.IMPLEMENTATION());
        uint256[] memory pks = _eoaKeys(4, 0xE0A0);
        for (uint256 i = 0; i < 4; i++) {
            ownerPks.push(pks[i]);
        }
        root = _safe(singleton141, _addrs(pks), 3, handler141);
        vm.prank(address(root));
        root.enableModule(module);
        vm.deal(address(root), 5 ether);

        // same people on the ECDSA side, 2 of the first 3
        uint256[] memory ecdsaSide = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            ecdsaSide[i] = pks[i];
        }
        sEcdsa = _safe150(_addrs(ecdsaSide), K);
        PQHolder[] memory hs = _pqHolders(3, 11);
        for (uint256 i = 0; i < 3; i++) {
            holders.push(hs[i]);
        }
        sPq = _safe150(_pqAddrs(hs), K);
    }

    function _common(address sPq_) internal view returns (Plan.Common memory c) {
        address[] memory modules = new address[](1);
        modules[0] = module;
        c = Plan.Common({
            multiSendCallOnly: multiSend,
            root: address(root),
            currentThreshold: root.getThreshold(),
            modules: modules,
            clearGuard: false,
            handler: address(0),
            lens: address(lens),
            k: K,
            pqImplementation: impl
        });
        sPq_;
    }

    function _threeOwners() internal view returns (uint256[] memory r) {
        r = new uint256[](3);
        r[0] = ownerPks[0];
        r[1] = ownerPks[2];
        r[2] = ownerPks[3];
    }

    function test_migrate141_then_nested() public {
        assertEq(root.VERSION(), "1.4.1");
        uint256 n0 = root.nonce();
        Plan.SafeTx memory tx1 = Plan.migrationTx(migration, false);
        Plan.SafeTx memory tx2 =
            Plan.nestedReconfigTx(_common(address(sPq)), root.getOwners(), address(sEcdsa), address(sPq));
        bytes32 h1 = _hashAt(root, tx1, n0);
        bytes32 h2 = _hashAt(root, tx2, n0 + 1); // both hashes can be signed before anything is executed

        uint256 g1 = _exec(root, tx1, _eoaSigs(h1, _threeOwners()));
        assertEq(root.VERSION(), "1.5.0");
        assertEq(lens.singletonOf(address(root)), singleton);
        assertEq(lens.fallbackHandlerOf(address(root)), handler);
        assertEq(root.getOwners().length, 4, "owners untouched by the migration");
        assertEq(_hash(root, tx2), h2, "SafeTx hash identical across 1.4.1 and 1.5.0");

        uint256 g2 = _exec(root, tx2, _eoaSigs(h2, _threeOwners()));
        lens.requireNested(address(root), address(sEcdsa), address(sPq), K, impl);
        assertEq(root.getThreshold(), 2);
        (address[] memory mods,) = root.getModulesPaginated(address(1), 10);
        assertEq(mods.length, 0);
        console.log("migration tx gas:", g1);
        console.log("reconfiguration batch gas:", g2);

        // the old owners alone can no longer move funds
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        vm.expectRevert();
        _exec(root, t, _eoaSigs(h, _threeOwners()));

        // the hybrid policy can
        _exec(root, t, _nestedSigs(h, sEcdsa, _pick(ownerPks, 0, 1), sPq, _pick(_holders(), 0, 2)));
        assertEq(beneficiary.balance, 1 ether);
    }

    /// A child that does not satisfy the policy makes the whole reconfiguration revert: nothing changes.
    function test_reconfig_revertsAtomically_onPolicyViolation() public {
        _exec(
            root,
            Plan.migrationTx(migration, false),
            _eoaSigs(_hash(root, Plan.migrationTx(migration, false)), _threeOwners())
        );
        ISafeExec weakPq = _safe150(_pqAddrs(_holders()), 1); // threshold 1 < K
        Plan.SafeTx memory tx2 =
            Plan.nestedReconfigTx(_common(address(weakPq)), root.getOwners(), address(sEcdsa), address(weakPq));
        bytes memory sigs = _eoaSigs(_hash(root, tx2), _threeOwners());
        // execTransaction with safeTxGas = 0 bubbles the lens error through MultiSendCallOnly
        uint256 flags = lens.CHILD_THRESHOLD() << lens.PQ_SHIFT();
        vm.expectRevert(abi.encodeWithSelector(ZKNOX_SafePQLens.HybridPolicyViolation.selector, flags));
        _exec(root, tx2, sigs);
        assertEq(root.getOwners().length, 4);
        assertEq(root.getThreshold(), 3);
    }

    function test_migrate141_L2_flavour() public {
        Plan.SafeTx memory tx1 = Plan.migrationTx(migration, true);
        _exec(root, tx1, _eoaSigs(_hash(root, tx1), _threeOwners()));
        assertEq(lens.singletonOf(address(root)), singletonL2);
        assertTrue(lens.isSafe150(address(root)));
    }

    function test_plan_refuses_child_already_owner() public {
        address[] memory owners = root.getOwners();
        vm.expectRevert(abi.encodeWithSelector(Plan.OwnerAlreadyPresent.selector, owners[1]));
        this.planWith(owners, owners[1]);
    }

    function planWith(address[] memory owners, address sEcdsa_) external view returns (Plan.SafeTx memory) {
        return Plan.nestedReconfigTx(_common(address(sPq)), owners, sEcdsa_, address(sPq));
    }

    function _holders() internal view returns (PQHolder[] memory hs) {
        hs = new PQHolder[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            hs[i] = holders[i];
        }
    }
}
