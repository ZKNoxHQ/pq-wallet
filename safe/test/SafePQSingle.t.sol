// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./SafePQFixture.sol";

/// SINGLE policy: one Safe, 2 EOAs + 2 PQ clones, T = n + k = 3 with k = 1.
contract SafePQSingleTest is SafePQFixture {
    uint256 constant K = 1;
    uint256[] eoaPks;
    PQHolder h0;
    PQHolder h1;
    ISafeExec safe;
    address impl;

    function setUp() public override {
        super.setUp();
        impl = address(pqFactory.IMPLEMENTATION());
        uint256[] memory pks = _eoaKeys(2, 0x5100);
        eoaPks.push(pks[0]);
        eoaPks.push(pks[1]);
        safe = _safe150(_addrs(pks), 2);
        vm.deal(address(safe), 5 ether);
        h0 = _pqHolder(21);
        h1 = _pqHolder(22);
    }

    function _common() internal view returns (Plan.Common memory) {
        return Plan.Common({
            multiSendCallOnly: multiSend,
            root: address(safe),
            currentThreshold: safe.getThreshold(),
            modules: new address[](0),
            clearGuard: false,
            handler: address(0),
            lens: address(lens),
            k: K,
            pqImplementation: impl
        });
    }

    function _addPQ(uint256 newThreshold) internal view returns (Plan.SafeTx memory t, bytes memory sigs) {
        t = Plan.singleReconfigTx(_common(), _pair(address(h0.account), address(h1.account)), newThreshold);
        sigs = _eoaSigs(_hash(safe, t), _pick(eoaPks, 0, 1));
    }

    function test_single_reconfigure_and_exec_mixed() public {
        (Plan.SafeTx memory t, bytes memory sigs) = _addPQ(3);
        _exec(safe, t, sigs);
        lens.requireSingle(address(safe), K, impl);

        // 1 ECDSA + 2 PQ
        Plan.SafeTx memory pay = _transfer(1 ether);
        bytes32 h = _hash(safe, pay);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](3);
        s[0] = Sigs.ecdsa(vm.addr(eoaPks[1]), _rsv(eoaPks[1], h));
        s[1] = Sigs.contractSig(address(h0.account), _pqPayload(h0, h));
        s[2] = Sigs.contractSig(address(h1.account), _pqPayload(h1, h));
        _exec(safe, pay, Sigs.pack(s));
        assertEq(beneficiary.balance, 1 ether);

        // 2 ECDSA only: below the threshold
        pay = _transfer(1 ether);
        h = _hash(safe, pay);
        vm.expectRevert();
        _exec(safe, pay, _eoaSigs(h, _pick(eoaPks, 0, 1)));
    }

    function test_single_threshold_too_low_reverts() public {
        (Plan.SafeTx memory t, bytes memory sigs) = _addPQ(2); // 2 EOAs alone would reach T = 2
        uint256 flags = lens.SINGLE_THRESHOLD();
        vm.expectRevert(abi.encodeWithSelector(ZKNOX_SafePQLens.HybridPolicyViolation.selector, flags));
        _exec(safe, t, sigs);
        assertEq(safe.getOwners().length, 2);
    }
}
