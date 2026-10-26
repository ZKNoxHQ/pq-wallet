// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm, console} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ZKNOX_PQAccount7702} from "../src/ZKNOX_PQAccount7702.sol";
import {PQAccountTestBase} from "./PQAccountTestBase.sol";

/// The scenarios are the same for every post-quantum scheme; each derived test binds one verifier.
abstract contract PQAccountScenarios is PQAccountTestBase {
    // ------------------------------------------------------------------ EIP-7702, ERC-4337 path

    function test_7702_userOp_execute() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("hello from 7702 userOp"));
        bytes32 h = entryPoint.getUserOpHash(op);
        op.signature = _hybridSig(h);

        uint256 gasUsed = _handleOps(op);
        console.log("handleOps gas (7702, hybrid k1 + PQ):", gasUsed);

        assertEq(target.lastGreeting(), "hello from 7702 userOp");
        assertEq(entryPoint.getNonce(address(account), 0), 1);
    }

    function test_7702_userOp_wrongPostQuantumSignature() public {
        _delegateAndInitialize();
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("x"));
        bytes32 h = entryPoint.getUserOpHash(op);
        bytes memory pqSig = _signPostQuantum(h);
        pqSig[100] ^= 0x01;
        op.signature = abi.encode(preQKey, _signPreQuantum(h), postQKeyRef, pqSig);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));
    }

    function test_7702_userOp_wrongPreQuantumSignature() public {
        _delegateAndInitialize();
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("x"));
        bytes32 h = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x1234, h); // another k1 key
        op.signature = abi.encode(preQKey, abi.encodePacked(r, s, v), postQKeyRef, _signPostQuantum(h));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));
    }

    function test_7702_userOp_keyNotMatchingHash() public {
        _delegateAndInitialize();
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("x"));
        bytes32 h = entryPoint.getUserOpHash(op);
        // valid signatures, but the post-quantum key reference is not the registered one
        op.signature = abi.encode(preQKey, _signPreQuantum(h), abi.encodePacked(address(0xbeef)), _signPostQuantum(h));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));
    }

    /// A stub signature (real hybrid signature over another digest) must cost what a valid one costs:
    /// bundlers size `verificationGasLimit` from it.
    function test_7702_stubSignature_costsLikeValidOne() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("x"));
        bytes32 h = entryPoint.getUserOpHash(op);
        bytes memory valid = _hybridSig(h);
        bytes memory stub = _hybridSig(keccak256("stub digest"));

        op.signature = valid;
        vm.prank(address(entryPoint));
        uint256 g = gasleft();
        uint256 v1 = account.validateUserOp(op, h, 0);
        uint256 gasValid = g - gasleft();

        op.signature = stub;
        vm.prank(address(entryPoint));
        g = gasleft();
        uint256 v2 = account.validateUserOp(op, h, 0);
        uint256 gasStub = g - gasleft();

        assertEq(v1, 0, "valid");
        assertEq(v2, 1, "stub rejected");
        console.log("validateUserOp gas, valid / stub:", gasValid, gasStub);
        // within 2%: the post-quantum verifier runs to its last comparison in both cases
        assertApproxEqRel(gasStub, gasValid, 0.02e18);
    }

    // ------------------------------------------------------------------ EIP-7702, direct and relayed paths

    /// Documents the 7702 caveat: the EOA key alone drives `execute`, the post-quantum key is not consulted.
    function test_7702_eoaDirectExecute_bypassesPQ() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        vm.prank(eoa);
        account.execute(address(target), 1 ether, abi.encodeWithSignature("sayHello(string)", "direct"));
        assertEq(target.lastGreeting(), "direct");
        assertEq(target.received(), 1 ether);
    }

    function test_7702_executeWithHybridSig_relayed_and_noReplay() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        BaseAccount.Call[] memory calls = new BaseAccount.Call[](2);
        calls[0] =
            BaseAccount.Call(address(target), 0.5 ether, abi.encodeWithSignature("sayHello(string)", "relayed 1"));
        calls[1] = BaseAccount.Call(address(target), 0, abi.encodeWithSignature("sayHello(string)", "relayed 2"));
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = account.hashExecute(calls, account.pqNonce(), deadline);
        bytes memory sig = _hybridSig(digest);

        uint256 g = gasleft();
        vm.prank(relayer);
        account.executeWithHybridSig(calls, deadline, sig);
        console.log("executeWithHybridSig gas (relayed, 2 calls):", g - gasleft());

        assertEq(target.lastGreeting(), "relayed 2");
        assertEq(target.received(), 0.5 ether);
        assertEq(account.pqNonce(), 1);

        // same signature again: nonce moved, digest differs, signature invalid
        vm.expectRevert(ZKNOX_PQAccount7702.InvalidSignature.selector);
        vm.prank(relayer);
        account.executeWithHybridSig(calls, deadline, sig);

        // expired
        bytes32 digest2 = account.hashExecute(calls, 1, deadline);
        bytes memory sig2 = _hybridSig(digest2);
        vm.warp(deadline + 1);
        vm.expectRevert(ZKNOX_PQAccount7702.Expired.selector);
        account.executeWithHybridSig(calls, deadline, sig2);
    }

    function test_7702_erc1271_wrappedHash() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        bytes32 appHash = keccak256("some dApp message");
        bytes memory sig = _hybridSig(account.hashWrapped(appHash));
        assertEq(account.isValidSignature(appHash, sig), IERC1271.isValidSignature.selector);
        // a signature over the raw hash is not accepted (domain binding)
        bytes memory rawSig = _hybridSig(appHash);
        assertEq(account.isValidSignature(appHash, rawSig), bytes4(0xffffffff));
    }

    // ------------------------------------------------------------------ initialization and storage

    function test_7702_initialize_onlySelfOrFactory_andOnce() public {
        Vm.SignedDelegation memory d = vm.signDelegation(address(impl), EOA_PK);
        vm.attachDelegation(d);
        ZKNOX_PQAccount7702 account = ZKNOX_PQAccount7702(payable(eoa));
        assertFalse(account.isInitialized());

        // front-runner
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ZKNOX_PQAccount7702.NotAuthorized.selector);
        account.initialize(abi.encodePacked(makeAddr("attacker")), postQRawKey);

        vm.prank(eoa);
        account.initialize(preQKey, postQRawKey);
        assertTrue(account.isInitialized());

        vm.prank(eoa);
        vm.expectRevert(ZKNOX_PQAccount7702.AlreadyInitialized.selector);
        account.initialize(preQKey, postQRawKey);
    }

    function test_7702_initializeWithKeyRefs() public {
        // the post-quantum key blob is written first, by anyone
        bytes memory ref = pqVerifier.setKey(postQRawKey);
        Vm.SignedDelegation memory d = vm.signDelegation(address(impl), EOA_PK);
        vm.attachDelegation(d);
        ZKNOX_PQAccount7702 account = ZKNOX_PQAccount7702(payable(eoa));
        vm.prank(eoa);
        account.initializeWithKeyRefs(preQKey, ref);
        postQKeyRef = ref;
        vm.deal(eoa, 1 ether);

        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("refs"));
        op.signature = _hybridSig(entryPoint.getUserOpHash(op));
        _handleOps(op);
        assertEq(target.lastGreeting(), "refs");
    }

    function test_7702_storageIsNamespaced() public {
        _delegateAndInitialize();
        for (uint256 slot = 0; slot < 8; slot++) {
            assertEq(vm.load(eoa, bytes32(slot)), bytes32(0), "low slot written");
        }
        bytes32 base = 0xa1c9fb4003d093dfa2fe8a427dd689f47e37fcf22ffa0fca873be97f59ccf300;
        assertEq(vm.load(eoa, base), keccak256(preQKey));
        assertEq(vm.load(eoa, bytes32(uint256(base) + 1)), keccak256(postQKeyRef));
    }

    function test_7702_rotatePreQuantumKey_viaUserOp() public {
        ZKNOX_PQAccount7702 account = _delegateAndInitialize();
        uint256 newPk = 0xc0ffee;
        bytes memory newKey = abi.encodePacked(vm.addr(newPk));

        PackedUserOperation memory op =
            _userOp(eoa, 0, abi.encodeWithSelector(ZKNOX_PQAccount7702.setPreQuantumKey.selector, newKey));
        op.signature = _hybridSig(entryPoint.getUserOpHash(op));
        _handleOps(op);
        (bytes32 preH,) = account.keyHashes();
        assertEq(preH, keccak256(newKey));

        // old k1 key no longer accepted, new one is
        PackedUserOperation memory op2 = _userOp(eoa, 1, _helloCallData("rotated"));
        bytes32 h2 = entryPoint.getUserOpHash(op2);
        bytes memory pqSig = _signPostQuantum(h2);
        op2.signature = abi.encode(preQKey, _signPreQuantum(h2), postQKeyRef, pqSig);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op2;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newPk, h2);
        op2.signature = abi.encode(newKey, abi.encodePacked(r, s, v), postQKeyRef, pqSig);
        _handleOps(op2);
        assertEq(target.lastGreeting(), "rotated");
    }

    function test_4337_factoryClone_withKeyRefs() public {
        bytes memory ref = pqVerifier.setKey(postQRawKey); // blob written beforehand, by anyone
        address predicted = factory.getAddress(preQKey, ref, 7);
        ZKNOX_PQAccount7702 account = factory.createAccountWithKeyRefs(preQKey, ref, 7);
        assertEq(address(account), predicted);
        (bytes32 preH, bytes32 postH) = account.keyHashes();
        assertEq(preH, keccak256(preQKey));
        assertEq(postH, keccak256(ref));
        assertEq(address(factory.createAccountWithKeyRefs(preQKey, ref, 7)), predicted, "idempotent");
        postQKeyRef = ref;
        vm.deal(address(account), 1 ether);
        PackedUserOperation memory op = _userOp(address(account), 0, _helloCallData("refs clone"));
        op.signature = _hybridSig(entryPoint.getUserOpHash(op));
        _handleOps(op);
        assertEq(target.lastGreeting(), "refs clone");
    }

    // ------------------------------------------------------------------ ERC-4337 clone path (no EOA)

    function test_4337_factoryClone_userOp() public {
        address predicted = factory.getAddress(preQKey, postQRawKey, 0);
        ZKNOX_PQAccount7702 account = factory.createAccount(preQKey, postQRawKey, 0);
        assertEq(address(account), predicted);
        assertTrue(account.isInitialized());
        _readBackPostQKeyRef(account);
        vm.deal(address(account), 10 ether);

        // idempotent
        assertEq(address(factory.createAccount(preQKey, postQRawKey, 0)), predicted);

        // nobody else can (re)initialize a clone
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ZKNOX_PQAccount7702.NotAuthorized.selector);
        account.initialize(preQKey, postQRawKey);

        // the k1 key alone cannot execute on a clone: no protocol-level authority here
        vm.prank(eoa);
        vm.expectRevert(ZKNOX_PQAccount7702.NotAuthorized.selector);
        account.execute(address(target), 0, "");

        PackedUserOperation memory op = _userOp(address(account), 0, _helloCallData("hello from 4337 clone"));
        op.signature = _hybridSig(entryPoint.getUserOpHash(op));
        uint256 gasUsed = _handleOps(op);
        console.log("handleOps gas (4337 clone, hybrid k1 + PQ):", gasUsed);
        assertEq(target.lastGreeting(), "hello from 4337 clone");
    }
}
