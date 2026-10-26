// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import "./SafePQFixture.sol";

/// NESTED policy with real ML-DSA-44 signatures: root (2/2) = S_ecdsa (2/3 EOAs) + S_pq (2/3 PQ clones).
contract SafePQNestedTest is SafePQFixture {
    uint256 constant K = 2;
    uint256[] eoaPks;
    PQHolder[] holders;
    ISafeExec sEcdsa;
    ISafeExec sPq;
    ISafeExec root;

    function setUp() public override {
        super.setUp();
        uint256[] memory pks = _eoaKeys(3, 0xA11CE);
        for (uint256 i = 0; i < 3; i++) {
            eoaPks.push(pks[i]);
        }
        PQHolder[] memory hs = _pqHolders(3, 1);
        for (uint256 i = 0; i < 3; i++) {
            holders.push(hs[i]);
        }
        sEcdsa = _safe150(_addrs(pks), K);
        sPq = _safe150(_pqAddrs(hs), K);
        root = _safe150(_pair(address(sEcdsa), address(sPq)), 2);
        vm.deal(address(root), 10 ether);
    }

    function _holders() internal view returns (PQHolder[] memory hs) {
        hs = new PQHolder[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            hs[i] = holders[i];
        }
    }

    function test_nested_lens_ok() public view {
        assertEq(
            lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, address(pqFactory.IMPLEMENTATION())),
            0
        );
        lens.requireNested(address(root), address(sEcdsa), address(sPq), K, address(pqFactory.IMPLEMENTATION()));
        assertEq(
            uint8(lens.classify(address(holders[0].account), address(pqFactory.IMPLEMENTATION()))),
            uint8(ZKNOX_SafePQLens.AccountKind.PQ_CLONE)
        );
        assertEq(uint8(lens.classify(vm.addr(eoaPks[0]), address(0))), uint8(ZKNOX_SafePQLens.AccountKind.EOA));
        assertEq(uint8(lens.classify(address(root), address(0))), uint8(ZKNOX_SafePQLens.AccountKind.SAFE_150));
    }

    function test_nested_exec_2ecdsa_2pq() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        bytes memory sigs = _nestedSigs(h, sEcdsa, _pick(eoaPks, 0, 2), sPq, _pick(_holders(), 1, 2));
        uint256 gasUsed = _exec(root, t, sigs);
        assertEq(beneficiary.balance, 1 ether);
        assertEq(root.nonce(), 1);

        // the two expanded ML-DSA-65 keys ride in the signature, 38,112 bytes each
        bytes memory cd = abi.encodeWithSelector(
            ISafeExec.execTransaction.selector,
            t.to, t.value, t.data, t.operation, uint256(0), uint256(0), uint256(0),
            address(0), payable(address(0)), sigs
        );
        uint256 zeros;
        for (uint256 i = 0; i < cd.length; i++) {
            if (cd[i] == 0) zeros++;
        }
        uint256 calldataGas = (cd.length - zeros) * 16 + zeros * 4;
        console.log("nested execTransaction, 2 ECDSA + 2 hybrid (k1 + ML-DSA-65) owners");
        console.log("  signature bytes", sigs.length, "calldata bytes", cd.length);
        console.log("  calldata gas", calldataGas, "execution", gasUsed);
        console.log("  transaction total", 21000 + calldataGas + gasUsed);

        // geth refuses to relay a transaction above 128 kB: two post-quantum
        // owners fit, and that is what caps k on this path
        assertLt(cd.length, 128 * 1024, "the transaction must stay under the mempool size limit");
        assertGt(sigs.length, 2 * 38112, "both expanded keys travel in the signature");
    }

    function test_nested_replay_rejected() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes memory sigs = _nestedSigs(_hash(root, t), sEcdsa, _pick(eoaPks, 0, 1), sPq, _pick(_holders(), 0, 1));
        _exec(root, t, sigs);
        vm.expectRevert();
        _exec(root, t, sigs);
    }

    function test_nested_onePQ_rejected() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] =
            Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), h), _pick(eoaPks, 0, 1)));
        s[1] = Sigs.contractSig(address(sPq), _pqSigs(Sigs.safeMessageHash(address(sPq), h), _one(holders[0])));
        vm.expectRevert();
        _exec(root, t, Sigs.pack(s));
    }

    function test_nested_oneECDSA_rejected() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), h), _one(eoaPks[0])));
        s[1] = Sigs.contractSig(address(sPq), _pqSigs(Sigs.safeMessageHash(address(sPq), h), _pick(_holders(), 0, 1)));
        vm.expectRevert();
        _exec(root, t, Sigs.pack(s));
    }

    function test_nested_pqSideOnly_rejected() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](1);
        s[0] = Sigs.contractSig(address(sPq), _pqSigs(Sigs.safeMessageHash(address(sPq), h), _pick(_holders(), 0, 1)));
        vm.expectRevert();
        _exec(root, t, Sigs.pack(s));
    }

    /// PQ payloads bound to S_ecdsa's SafeMessage domain do not validate for S_pq.
    function test_nested_crossChildDigest_rejected() public {
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] =
            Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), h), _pick(eoaPks, 0, 1)));
        s[1] =
            Sigs.contractSig(address(sPq), _pqSigs(Sigs.safeMessageHash(address(sEcdsa), h), _pick(_holders(), 0, 1)));
        vm.expectRevert();
        _exec(root, t, Sigs.pack(s));
    }

    /// On-chain approvals: each child executes root.approveHash(h) with its own owners, then anyone executes the root.
    function test_nested_approveHash_path() public {
        Plan.SafeTx memory t = _transfer(2 ether);
        bytes32 h = _hash(root, t);
        Plan.SafeTx memory approve =
            Plan.SafeTx({to: address(root), value: 0, data: abi.encodeCall(ISafeExec.approveHash, (h)), operation: 0});

        bytes memory ecdsaSigs = _eoaSigs(_hash(sEcdsa, approve), _pick(eoaPks, 1, 2));
        _exec(sEcdsa, approve, ecdsaSigs);
        bytes memory pqSigs = _pqSigs(_hash(sPq, approve), _pick(_holders(), 0, 2));
        uint256 pqGas = _exec(sPq, approve, pqSigs);

        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.approved(address(sEcdsa));
        s[1] = Sigs.approved(address(sPq));
        bytes memory rootSigs = Sigs.pack(s);
        uint256 rootGas = _exec(root, t, rootSigs);
        assertEq(beneficiary.balance, 2 ether);

        // The heavy payload moves to S_pq's own approveHash transaction; the root
        // transaction carries two 65-byte v=1 slots and nothing else, so it fits
        // anywhere a plain Safe transaction fits.
        console.log("S_pq approveHash: signature bytes", pqSigs.length, "execution", pqGas);
        console.log("root execTransaction: signature bytes", rootSigs.length, "execution", rootGas);
        assertEq(rootSigs.length, 130, "two approved-hash slots");
        assertGt(pqSigs.length, 2 * 38112, "both expanded keys travel in the child transaction");

        // EIP-7623 floor on S_pq's transaction: it carries the two expanded keys
        bytes memory cd = abi.encodeWithSelector(
            ISafeExec.execTransaction.selector,
            approve.to, approve.value, approve.data, approve.operation,
            uint256(0), uint256(0), uint256(0), address(0), payable(address(0)), pqSigs
        );
        uint256 zeros;
        for (uint256 i = 0; i < cd.length; i++) {
            if (cd[i] == 0) zeros++;
        }
        uint256 tokens = zeros + 4 * (cd.length - zeros);
        uint256 floorTotal = 21000 + 10 * tokens;
        uint256 standardTotal = 21000 + (cd.length - zeros) * 16 + zeros * 4 + pqGas;
        console.log("  calldata bytes", cd.length, "EIP-7623 floor", floorTotal);
        console.log("  standard total", standardTotal);
        assertGt(standardTotal, floorTotal, "execution must clear the EIP-7623 floor");
        assertLt(standardTotal, 16777216, "under the EIP-7825 per-transaction cap");
    }

    // ---- lens negative cases (configuration changed through self-calls, i.e. what an authorized tx would do)

    function test_lens_flags_module_on_pq_child() public {
        vm.prank(address(sPq));
        sPq.enableModule(makeAddr("module"));
        uint256 v =
            lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, address(pqFactory.IMPLEMENTATION()));
        assertEq(v, lens.CHILD_MODULES() << lens.PQ_SHIFT());
    }

    function test_lens_flags_threshold_and_handler_on_ecdsa_child() public {
        vm.startPrank(address(sEcdsa));
        sEcdsa.changeThreshold(1);
        sEcdsa.setFallbackHandler(handler141);
        vm.stopPrank();
        address impl = address(pqFactory.IMPLEMENTATION());
        uint256 v = lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, impl);
        assertEq(v, (lens.CHILD_THRESHOLD() | lens.CHILD_HANDLER()) << lens.ECDSA_SHIFT());
        vm.expectRevert(abi.encodeWithSelector(ZKNOX_SafePQLens.HybridPolicyViolation.selector, v));
        lens.requireNested(address(root), address(sEcdsa), address(sPq), K, impl);
    }

    function test_lens_flags_swapped_children() public view {
        uint256 v =
            lens.nestedViolations(address(root), address(sPq), address(sEcdsa), K, address(pqFactory.IMPLEMENTATION()));
        assertEq(v, (lens.CHILD_OWNERS() << lens.ECDSA_SHIFT()) | (lens.CHILD_OWNERS() << lens.PQ_SHIFT()));
    }

    function test_lens_flags_root_module_and_owner_count() public {
        vm.prank(address(root));
        root.enableModule(makeAddr("module"));
        assertEq(
            lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, address(pqFactory.IMPLEMENTATION())),
            lens.ROOT_MODULES()
        );
        // wrong implementation: the clones are not recognized as PQ owners
        assertEq(
            lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, makeAddr("otherImpl")),
            lens.ROOT_MODULES() | (lens.CHILD_OWNERS() << lens.PQ_SHIFT())
        );
    }
}
