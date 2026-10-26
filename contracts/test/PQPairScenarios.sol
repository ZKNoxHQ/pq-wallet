// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm, console} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ZKNOX_PQAccount7702} from "../src/ZKNOX_PQAccount7702.sol";
import {ZKNOX_PQSatellite7702} from "../src/ZKNOX_PQSatellite7702.sol";
import {PQAccountTestBase} from "./PQAccountTestBase.sol";

/// Two pots: the vault (clone, hybrid PQ authorization, no EOA key) and the EOA delegated to the satellite.
abstract contract PQPairScenarios is PQAccountTestBase {
    uint256 constant RESERVE = 0.05 ether;

    function test_pair_setup_and_storage() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        assertEq(satellite.vault(), address(vault));
        assertEq(satellite.gasReserve(), RESERVE);
        assertTrue(vault.isInitialized());
        for (uint256 slot = 0; slot < 8; slot++) {
            assertEq(vm.load(eoa, bytes32(slot)), bytes32(0), "low slot written");
        }
        bytes32 base = 0x7dc0ab30d2f010c5a0e75ae2fda8bbc28fbe8f603021c67276e67f72622c3f00;
        assertEq(address(uint160(uint256(vm.load(eoa, base)))), address(vault));
    }

    function test_pair_initialize_onlySelf_once() public {
        ZKNOX_PQAccount7702 vault = factory.createAccount(preQKey, postQRawKey, 0);
        Vm.SignedDelegation memory d = vm.signDelegation(address(satelliteImpl), EOA_PK);
        vm.attachDelegation(d);
        ZKNOX_PQSatellite7702 satellite = ZKNOX_PQSatellite7702(payable(eoa));

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ZKNOX_PQSatellite7702.NotAuthorized.selector);
        satellite.initialize(makeAddr("attacker"), 0);

        vm.prank(eoa);
        satellite.initialize(address(vault), RESERVE);
        vm.prank(eoa);
        vm.expectRevert(ZKNOX_PQSatellite7702.AlreadyInitialized.selector);
        satellite.initialize(address(vault), RESERVE);
    }

    /// Incoming funds on the public address reach the post-quantum pot without any signature.
    function test_pair_sweep_eth_and_tokens_byAnyone() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        vm.deal(eoa, 3 ether);
        token.mint(eoa, 1_000e18);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        vm.prank(makeAddr("keeper"));
        satellite.sweep(tokens);

        assertEq(eoa.balance, RESERVE, "reserve kept");
        assertEq(address(vault).balance, 3 ether - RESERVE, "eth swept");
        assertEq(token.balanceOf(address(vault)), 1_000e18, "tokens swept");
        assertEq(token.balanceOf(eoa), 0);

        // nothing above the reserve: no-op
        vm.prank(makeAddr("keeper"));
        satellite.sweep(tokens);
        assertEq(eoa.balance, RESERVE);
    }

    /// The EOA key alone cannot touch the vault.
    function test_pair_vault_notSpendableByEoaKey() public {
        (ZKNOX_PQAccount7702 vault,) = _createPair(RESERVE);
        vm.deal(address(vault), 1 ether);
        vm.prank(eoa);
        vm.expectRevert(ZKNOX_PQAccount7702.NotAuthorized.selector);
        vault.execute(address(target), 1 ether, "");
        assertEq(address(vault).balance, 1 ether);
    }

    /// The EOA spends vault funds with a post-quantum transaction: it relays the hybrid signature.
    function test_pair_eoa_relaysHybridSig_spendsVault() public {
        (ZKNOX_PQAccount7702 vault,) = _createPair(RESERVE);
        vm.deal(address(vault), 2 ether);
        vm.deal(eoa, 1 ether);
        BaseAccount.Call[] memory calls = new BaseAccount.Call[](1);
        calls[0] = BaseAccount.Call(address(target), 1 ether, abi.encodeWithSignature("sayHello(string)", "from vault"));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _hybridSig(vault.hashExecute(calls, 0, deadline));

        vm.prank(eoa, eoa);
        vault.executeWithHybridSig(calls, deadline, sig);

        assertEq(target.received(), 1 ether);
        assertEq(target.lastSender(), address(vault));
        assertEq(address(vault).balance, 1 ether);
    }

    /// One hybrid signature, msg.sender == EOA: the vault pushes funds to the EOA and executes through it.
    function test_pair_vault_actsAsEoa_atomically() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        vm.deal(address(vault), 2 ether);
        assertEq(eoa.balance, 0);

        bytes memory inner = abi.encodeWithSelector(
            BaseAccount.execute.selector,
            address(target),
            1 ether,
            abi.encodeWithSignature("sayHello(string)", "as eoa")
        );
        BaseAccount.Call[] memory calls = new BaseAccount.Call[](2);
        calls[0] = BaseAccount.Call(eoa, 1 ether, "");
        calls[1] = BaseAccount.Call(eoa, 0, inner);

        PackedUserOperation memory op =
            _userOp(address(vault), 0, abi.encodeWithSelector(BaseAccount.executeBatch.selector, calls));
        op.signature = _hybridSig(entryPoint.getUserOpHash(op));
        uint256 gasUsed = _handleOps(op);
        console.log("handleOps gas (vault acting as EOA, 2-call batch):", gasUsed);

        assertEq(target.received(), 1 ether);
        assertEq(target.lastSender(), eoa, "dApp sees the EOA");
        assertEq(eoa.balance, 0, "nothing left on the EOA");
        assertEq(satellite.vault(), address(vault));
    }

    function test_pair_satellite_executeAuth() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        vm.deal(eoa, 1 ether);
        bytes memory data = abi.encodeWithSignature("sayHello(string)", "x");

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ZKNOX_PQSatellite7702.NotAuthorized.selector);
        satellite.execute(address(target), 0.1 ether, data);

        vm.prank(address(vault));
        satellite.execute(address(target), 0.1 ether, data);
        vm.prank(eoa);
        satellite.execute(address(target), 0.1 ether, data);
        assertEq(target.received(), 0.2 ether);
    }

    /// Non-post-quantum pot: the EOA key alone signs userOps for the satellite.
    function test_pair_satellite_userOp_ecdsaOnly() public {
        (, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        vm.deal(eoa, 1 ether);
        PackedUserOperation memory op = _userOp(eoa, 0, _helloCallData("satellite userOp"));
        bytes32 h = entryPoint.getUserOpHash(op);
        op.signature = _signPreQuantum(h);
        uint256 gasUsed = _handleOps(op);
        console.log("handleOps gas (satellite, ECDSA only):", gasUsed);
        assertEq(target.lastGreeting(), "satellite userOp");
        assertEq(target.lastSender(), eoa);

        // another key is rejected
        PackedUserOperation memory op2 = _userOp(eoa, 1, _helloCallData("x"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x1234, entryPoint.getUserOpHash(op2));
        op2.signature = abi.encodePacked(r, s, v);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op2;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));
        (satellite);
    }

    /// A signature in the name of the EOA requires the vault's hybrid keys, and is bound to the EOA.
    function test_pair_erc1271_relayedToVault() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        bytes32 appHash = keccak256("dApp message for the EOA");
        bytes memory sig = _hybridSig(satellite.hashWrapped(appHash));
        assertEq(satellite.isValidSignature(appHash, sig), IERC1271.isValidSignature.selector);

        // not valid as a direct vault signature over the same hash
        assertEq(vault.isValidSignature(appHash, sig), bytes4(0xffffffff));
        // the EOA key alone is not a hybrid signature: the vault rejects it (revert on decoding, which
        // ERC-1271 allows and OZ SignatureChecker treats as invalid)
        bytes memory ecdsaOnly = _signPreQuantum(appHash);
        (bool ok, bytes memory ret) = address(satellite)
            .staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, appHash, ecdsaOnly));
        assertTrue(!ok || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector);
    }

    /// Settings are changeable by the vault (hybrid signature) as well as by the EOA key.
    function test_pair_settings_byVault() public {
        (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite) = _createPair(RESERVE);
        vm.prank(address(vault));
        satellite.setGasReserve(1 ether);
        assertEq(satellite.gasReserve(), 1 ether);

        vm.prank(makeAddr("attacker"));
        vm.expectRevert(ZKNOX_PQSatellite7702.NotAuthorized.selector);
        satellite.setVault(makeAddr("attacker"));

        vm.prank(eoa);
        vm.expectRevert(ZKNOX_PQSatellite7702.ZeroVault.selector);
        satellite.setVault(address(0));
    }
}
