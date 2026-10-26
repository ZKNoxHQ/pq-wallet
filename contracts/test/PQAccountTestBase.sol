// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BaseAccount} from "account-abstraction/contracts/core/BaseAccount.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {ECDSAk1Verifier} from "InterfaceVerifier/VerifierECDSAk1.sol";
import {ZKNOX_PQAccount7702} from "../src/ZKNOX_PQAccount7702.sol";
import {ZKNOX_PQFactory7702} from "../src/ZKNOX_PQFactory7702.sol";
import {ZKNOX_PQSatellite7702} from "../src/ZKNOX_PQSatellite7702.sol";
import {TestToken} from "../src/TestToken.sol";

contract TestTarget {
    event Hello(string greeting);

    string public lastGreeting;
    uint256 public received;
    address public lastSender;

    function sayHello(string memory greeting) external payable {
        lastGreeting = greeting;
        received += msg.value;
        lastSender = msg.sender;
        emit Hello(greeting);
    }
}

/// Common fixture: Keccak-f[1600] helper, EntryPoint v0.8, k1 verifier, factory + implementation.
/// Derived tests provide the post-quantum verifier, the raw post-quantum key and a signing oracle.
abstract contract PQAccountTestBase is Test {
    // the EOA: its secp256k1 key is also the pre-quantum key of the account
    uint256 internal constant EOA_PK = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
    address internal eoa;

    address internal f1600Helper; // Fireblocks f1600_170.hex, bound by ZKNOX_dilithium
    address internal f1600ZknoxHelper; // ETHFALCON f1600_zknox.hex, bound by ZKNOX_falcon8
    EntryPoint internal entryPoint;
    ECDSAk1Verifier internal k1;
    ISigVerifier internal pqVerifier;
    ZKNOX_PQFactory7702 internal factory;
    ZKNOX_PQAccount7702 internal impl;
    ZKNOX_PQSatellite7702 internal satelliteImpl;
    TestToken internal token;
    TestTarget internal target;
    address internal beneficiary = makeAddr("beneficiary");
    address internal relayer = makeAddr("relayer");

    bytes internal preQKey; // normalized pre-quantum key (20-byte address)
    bytes internal postQRawKey; // raw post-quantum key, as given to `initialize`
    bytes internal postQKeyRef; // normalized post-quantum key (SSTORE2 pointer), read back after init

    // ---- to be provided by the derived test ----
    function _deployPQVerifier() internal virtual returns (ISigVerifier);
    function _rawPostQuantumKey() internal virtual returns (bytes memory);
    function _signPostQuantum(bytes32 digest) internal virtual returns (bytes memory);

    function setUp() public virtual {
        eoa = vm.addr(EOA_PK);
        f1600Helper = _deployHelper("../lib/ETHDILITHIUM/test/f1600_170.hex");
        f1600ZknoxHelper = _deployHelper("../lib/ETHFALCON/test/f1600_zknox.hex");
        entryPoint = new EntryPoint();
        k1 = new ECDSAk1Verifier();
        pqVerifier = _deployPQVerifier();
        factory = new ZKNOX_PQFactory7702(entryPoint, k1, pqVerifier, "test");
        impl = factory.IMPLEMENTATION();
        satelliteImpl = new ZKNOX_PQSatellite7702(entryPoint);
        token = new TestToken();
        target = new TestTarget();
        preQKey = abi.encodePacked(eoa);
        postQRawKey = _rawPostQuantumKey();
    }

    function _deployHelper(string memory path) internal returns (address helper) {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = path;
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "helper: CREATE failed");
    }

    // ---- EIP-7702 ----

    /// Delegates `eoa` to the implementation and initializes it the way a type-4 transaction would:
    /// the EOA calls `initialize` on itself.
    function _delegateAndInitialize() internal returns (ZKNOX_PQAccount7702 account) {
        Vm.SignedDelegation memory d = vm.signDelegation(address(impl), EOA_PK);
        vm.attachDelegation(d);
        account = ZKNOX_PQAccount7702(payable(eoa));
        vm.prank(eoa);
        account.initialize(preQKey, postQRawKey);
        _readBackPostQKeyRef(account);
        vm.deal(eoa, 10 ether);
    }

    /// The account keeps only the hash of the normalized key, whatever shape the verifier gives it: the key
    /// itself for a stateless verifier (ML-DSA in calldata), an SSTORE2 pointer for one that deposits. The
    /// derived test says which, and this checks the account registered it.
    function _readBackPostQKeyRef(ZKNOX_PQAccount7702 account) internal {
        postQKeyRef = _normalizedPostQuantumKey();
        (bytes32 preH, bytes32 postH) = account.keyHashes();
        assertEq(preH, keccak256(preQKey), "preQ hash");
        assertEq(postH, keccak256(postQKeyRef), "postQ hash");
    }

    /// What `ISigVerifier.setKey` returned for `postQRawKey`. Default: the key itself, which is what a
    /// verifier holding no state hands back. A depositing verifier overrides this.
    function _normalizedPostQuantumKey() internal virtual returns (bytes memory) {
        return postQRawKey;
    }

    /// The SSTORE2 pointer a depositing verifier just wrote: its last created contract.
    function _lastSstore2Pointer() internal view returns (bytes memory) {
        uint64 n = vm.getNonce(address(pqVerifier));
        return abi.encodePacked(vm.computeCreateAddress(address(pqVerifier), n - 1));
    }

    // ---- vault + satellite pair ----

    /// Deploys the vault (clone, post-quantum pot) and delegates the EOA to the satellite linked to it.
    function _createPair(uint256 gasReserve)
        internal
        returns (ZKNOX_PQAccount7702 vault, ZKNOX_PQSatellite7702 satellite)
    {
        vault = factory.createAccount(preQKey, postQRawKey, 0);
        _readBackPostQKeyRef(vault);
        Vm.SignedDelegation memory d = vm.signDelegation(address(satelliteImpl), EOA_PK);
        vm.attachDelegation(d);
        satellite = ZKNOX_PQSatellite7702(payable(eoa));
        vm.prank(eoa);
        satellite.initialize(address(vault), gasReserve);
    }

    // ---- signatures ----

    function _signPreQuantum(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EOA_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hybridSig(bytes32 digest) internal returns (bytes memory) {
        return abi.encode(preQKey, _signPreQuantum(digest), postQKeyRef, _signPostQuantum(digest));
    }

    function _bytes32ToHex(bytes32 value) internal pure returns (string memory) {
        return Strings.toHexString(uint256(value), 32);
    }

    // ---- userOps ----

    function _userOp(address sender, uint256 nonce, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(3_000_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(2 gwei))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _helloCallData(string memory greeting) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            BaseAccount.execute.selector, address(target), 0, abi.encodeWithSignature("sayHello(string)", greeting)
        );
    }

    function _handleOps(PackedUserOperation memory op) internal returns (uint256 gasUsed) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        uint256 g = gasleft();
        vm.prank(relayer, relayer);
        entryPoint.handleOps(ops, payable(beneficiary));
        gasUsed = g - gasleft();
    }
}
