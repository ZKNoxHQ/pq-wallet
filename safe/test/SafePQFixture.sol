// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, Vm, console} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/contracts/core/EntryPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {ECDSAk1Verifier} from "InterfaceVerifier/VerifierECDSAk1.sol";
import {ZKNOX_dilithium65} from "ETHDILITHIUM/src/ZKNOX_dilithium65.sol";
import {KEY_BYTES65} from "ETHDILITHIUM/src/ZKNOX_dilithium65_core_packed.sol";
import {ZKNOX_PQAccount7702} from "pq-account/ZKNOX_PQAccount7702.sol";
import {ZKNOX_PQFactory7702} from "pq-account/ZKNOX_PQFactory7702.sol";

import {ZKNOX_SafePQLens} from "../src/ZKNOX_SafePQLens.sol";
import {ZKNOX_SafePQSignatures as Sigs} from "../src/libraries/ZKNOX_SafePQSignatures.sol";
import {ZKNOX_SafePQPlan as Plan} from "../src/libraries/ZKNOX_SafePQPlan.sol";

/// Safe 1.3.0+ ABI with the operation enum as uint8, valid for the 1.4.1 and 1.5.0 proxies alike.
interface ISafeExec {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce_
    ) external view returns (bytes32);
    function nonce() external view returns (uint256);
    function VERSION() external view returns (string memory);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function approveHash(bytes32 hash) external;
    function enableModule(address module) external;
    function changeThreshold(uint256 threshold) external;
    function setFallbackHandler(address handler) external;
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory, address);
}

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// Post-quantum verifier that accepts everything: models a broken ML-DSA/Falcon verifier.
contract AcceptAllVerifier is ISigVerifier {
    function setKey(bytes calldata key) external pure returns (bytes memory) {
        return key;
    }

    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bytes4) {
        return ISigVerifier.verify.selector;
    }
}

/// Holder of one ZKNOX_PQAccount7702 clone: its k1 key and ML-DSA seed.
struct PQHolder {
    uint256 k1Pk;
    string seed;
    ZKNOX_PQAccount7702 account;
    bytes preQKey; // 20-byte address
    bytes postQKeyRef; // the expanded ML-DSA-65 key itself, 38,112 bytes (raw key for AcceptAllVerifier)
}

abstract contract SafePQFixture is Test {
    string internal constant PQ_LIB = "../lib/";
    /// ML-DSA-65 keys and signatures, derived from a holder's 32-byte seed
    string internal constant SIGNER = "scripts/mldsa65.mjs";

    // ---- the account stack of ../contracts
    address internal f1600Helper;
    EntryPoint internal entryPoint;
    ECDSAk1Verifier internal k1;
    ZKNOX_dilithium65 internal mldsa;
    ZKNOX_PQFactory7702 internal pqFactory;

    // ---- Safe stack
    // compiled apart (test/safe/SafeArtifacts.sol, legacy pipeline), deployed from their artifacts
    string internal constant S150 = "../lib/safe-smart-account/contracts/";
    string internal constant S141 = "../lib/safe-smart-account-1.4.1/contracts/";
    address internal singleton;
    address internal singletonL2;
    address internal singleton141;
    ISafeProxyFactory internal proxyFactory;
    address internal handler;
    address internal handler141;
    address internal multiSend;
    address internal migration;
    ZKNOX_SafePQLens internal lens;

    address internal beneficiary = makeAddr("beneficiary");
    address internal relayer = makeAddr("relayer");
    uint256 internal saltNonce;

    function setUp() public virtual {
        f1600Helper = _deployHelper(string.concat(PQ_LIB, "ETHDILITHIUM/test/f1600_170.hex"));
        entryPoint = new EntryPoint();
        k1 = new ECDSAk1Verifier();
        mldsa = new ZKNOX_dilithium65(f1600Helper);
        pqFactory = new ZKNOX_PQFactory7702(entryPoint, k1, mldsa, "test");

        singleton = deployCode(_artifact(S150, "Safe.sol", "Safe"));
        singletonL2 = deployCode(_artifact(S150, "SafeL2.sol", "SafeL2"));
        singleton141 = deployCode(_artifact(S141, "Safe.sol", "Safe"));
        proxyFactory =
            ISafeProxyFactory(deployCode(_artifact(S150, "proxies/SafeProxyFactory.sol", "SafeProxyFactory")));
        handler =
            deployCode(_artifact(S150, "handler/CompatibilityFallbackHandler.sol", "CompatibilityFallbackHandler"));
        handler141 =
            deployCode(_artifact(S141, "handler/CompatibilityFallbackHandler.sol", "CompatibilityFallbackHandler"));
        multiSend = deployCode(_artifact(S150, "libraries/MultiSendCallOnly.sol", "MultiSendCallOnly"));
        migration = deployCode(
            _artifact(S150, "libraries/SafeMigration.sol", "SafeMigration"), abi.encode(singleton, singletonL2, handler)
        );
        lens = new ZKNOX_SafePQLens(singleton, singletonL2, handler);
        assertEq(ISafeExec(singleton).VERSION(), "1.5.0");
        assertEq(ISafeExec(singleton141).VERSION(), "1.4.1");
    }

    // ------------------------------------------------------------------ deployment helpers

    /// Artifact of `name` compiled from `root/rel`. Two Safe releases share file and contract names, so Forge
    /// disambiguates the output directories; the candidate whose compilation target is this source wins.
    function _artifact(string memory root, string memory rel, string memory name)
        internal
        view
        returns (string memory)
    {
        string memory source = string.concat(root, rel);
        string[] memory parts = vm.split(source, "/");
        string memory suffix = string.concat(parts[parts.length - 1], "/", name, ".json");
        for (uint256 i = parts.length - 1;; i--) {
            string memory candidate = string.concat("out/", suffix);
            if (vm.exists(candidate)) {
                string[] memory targets =
                    vm.parseJsonKeys(vm.readFile(candidate), ".metadata.settings.compilationTarget");
                if (targets.length == 1 && keccak256(bytes(targets[0])) == keccak256(bytes(source))) return candidate;
            }
            if (i == 0) break;
            suffix = string.concat(parts[i - 1], "/", suffix);
        }
        revert(string.concat("artifact not found: ", source));
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

    function _safe(address singleton_, address[] memory owners, uint256 threshold, address fallbackHandler)
        internal
        returns (ISafeExec safe)
    {
        bytes memory init = abi.encodeCall(
            ISafeExec.setup, (owners, threshold, address(0), "", fallbackHandler, address(0), 0, payable(address(0)))
        );
        safe = ISafeExec(proxyFactory.createProxyWithNonce(singleton_, init, ++saltNonce));
    }

    function _safe150(address[] memory owners, uint256 threshold) internal returns (ISafeExec) {
        return _safe(singleton, owners, threshold, handler);
    }

    function _eoaKeys(uint256 n, uint256 base) internal pure returns (uint256[] memory pks) {
        pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = base + i;
        }
    }

    function _addrs(uint256[] memory pks) internal pure returns (address[] memory a) {
        a = new address[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            a[i] = vm.addr(pks[i]);
        }
    }

    /// a holder's 32-byte seed, as hex without the 0x prefix
    function _seed(uint256 i) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory s = new bytes(64);
        for (uint256 j = 0; j < 64; j++) {
            s[j] = hexChars[(i + j * 7) % 16];
        }
        return string(s);
    }

    /// node scripts/mldsa65.mjs <cmd> <seed> [hash] -> hex, decoded by vm.ffi
    function _mldsa65(string memory cmd, string memory seed, string memory arg)
        internal
        returns (bytes memory)
    {
        string[] memory c = new string[](bytes(arg).length == 0 ? 4 : 5);
        c[0] = "node";
        c[1] = SIGNER;
        c[2] = cmd;
        c[3] = seed;
        if (bytes(arg).length != 0) c[4] = arg;
        return vm.ffi(c);
    }

    /// Clone created by the ML-DSA-65 factory. The post-quantum verifier keeps
    /// no state: setKey hands the expanded key back, so the account's
    /// postQKeyHash is keccak256 of that key and the key itself is what every
    /// signature carries.
    function _pqHolder(uint256 i) internal returns (PQHolder memory h) {
        h.k1Pk = 0xB0B0 + i;
        h.seed = _seed(i);
        h.preQKey = abi.encodePacked(vm.addr(h.k1Pk));
        h.postQKeyRef = _mldsa65("key", h.seed, "");
        require(h.postQKeyRef.length == KEY_BYTES65, "fixture: expanded key length");
        h.account = pqFactory.createAccount(h.preQKey, h.postQKeyRef, 0);
        (, bytes32 postH) = h.account.keyHashes();
        require(postH == keccak256(h.postQKeyRef), "fixture: key ref");
    }

    function _pqHolders(uint256 n, uint256 base) internal returns (PQHolder[] memory hs) {
        hs = new PQHolder[](n);
        for (uint256 i = 0; i < n; i++) {
            hs[i] = _pqHolder(base + i);
        }
    }

    function _pqAddrs(PQHolder[] memory hs) internal pure returns (address[] memory a) {
        a = new address[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            a[i] = address(hs[i].account);
        }
    }

    // ------------------------------------------------------------------ signing helpers

    function _rsv(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// ERC-1271 payload of a ZKNOX_PQAccount7702 clone for `hash` (k1 + ML-DSA-65
    /// over hashWrapped(hash)). The expanded key rides in the payload, so this
    /// is some 41.8 kB per post-quantum owner.
    function _pqPayload(PQHolder memory h, bytes32 hash) internal returns (bytes memory) {
        bytes32 d = Sigs.pqAccountDigest(address(h.account), hash);
        bytes memory sig = _mldsa65("sign", h.seed, _hex32(d));
        require(sig.length == 3309, "fixture: ML-DSA-65 signature length");
        return Sigs.hybridPayload(h.preQKey, _rsv(h.k1Pk, d), h.postQKeyRef, sig);
    }

    /// a bytes32 as 64 hex characters, no 0x prefix (the signer's argument)
    function _hex32(bytes32 v) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            out[2 * i] = hexChars[uint8(v[i]) >> 4];
            out[2 * i + 1] = hexChars[uint8(v[i]) & 0x0f];
        }
        return string(out);
    }

    /// Signature of Safe `safe` over `hash` by the EOAs `pks` (hash signed directly).
    function _eoaSigs(bytes32 hash, uint256[] memory pks) internal pure returns (bytes memory) {
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            s[i] = Sigs.ecdsa(vm.addr(pks[i]), _rsv(pks[i], hash));
        }
        return Sigs.pack(s);
    }

    /// Signature of a Safe whose owners are PQ clones `hs`, over `hash`.
    function _pqSigs(bytes32 hash, PQHolder[] memory hs) internal returns (bytes memory) {
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            s[i] = Sigs.contractSig(address(hs[i].account), _pqPayload(hs[i], hash));
        }
        return Sigs.pack(s);
    }

    /// Root signature for the NESTED policy: child Safes sign the root hash through their fallback handler.
    function _nestedSigs(
        bytes32 rootHash,
        ISafeExec sEcdsa,
        uint256[] memory eoaSigners,
        ISafeExec sPq,
        PQHolder[] memory pqSigners
    ) internal returns (bytes memory) {
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), rootHash), eoaSigners));
        s[1] = Sigs.contractSig(address(sPq), _pqSigs(Sigs.safeMessageHash(address(sPq), rootHash), pqSigners));
        return Sigs.pack(s);
    }

    function _hash(ISafeExec safe, Plan.SafeTx memory t) internal view returns (bytes32) {
        return _hashAt(safe, t, safe.nonce());
    }

    function _hashAt(ISafeExec safe, Plan.SafeTx memory t, uint256 nonce_) internal view returns (bytes32) {
        return safe.getTransactionHash(t.to, t.value, t.data, t.operation, 0, 0, 0, address(0), address(0), nonce_);
    }

    function _exec(ISafeExec safe, Plan.SafeTx memory t, bytes memory sigs) internal returns (uint256 gasUsed) {
        uint256 g = gasleft();
        vm.prank(relayer, relayer);
        safe.execTransaction(t.to, t.value, t.data, t.operation, 0, 0, 0, address(0), payable(address(0)), sigs);
        gasUsed = g - gasleft();
    }

    function _transfer(uint256 amount) internal view returns (Plan.SafeTx memory) {
        return Plan.SafeTx({to: beneficiary, value: amount, data: "", operation: 0});
    }

    // ------------------------------------------------------------------ small array helpers

    function _pick(uint256[] memory a, uint256 i, uint256 j) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a[i];
        r[1] = a[j];
    }

    function _pick(PQHolder[] memory a, uint256 i, uint256 j) internal pure returns (PQHolder[] memory r) {
        r = new PQHolder[](2);
        r[0] = a[i];
        r[1] = a[j];
    }

    function _one(PQHolder memory h) internal pure returns (PQHolder[] memory r) {
        r = new PQHolder[](1);
        r[0] = h;
    }

    function _one(uint256 pk) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = pk;
    }

    function _pair(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2);
        r[0] = a;
        r[1] = b;
    }
}
