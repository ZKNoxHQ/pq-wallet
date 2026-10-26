// SPDX-License-Identifier: MIT
// A public key produced by the ECML-Signer Ledger app as a post-quantum owner
// of a Safe, and the digest that device has to sign for a root transaction.
pragma solidity ^0.8.25;

import "./SafePQFixture.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

/// The key and signatures come from ETHDILITHIUM's test/KAT/ecml_device_vectors.json:
/// the release ELF of ZKNoxHQ/ecml-signer run under speculos, through
/// HYBRID_SIGN_HASH (0x16) and SIGN_TX_MLDSA (0x08), P2 = ML-DSA-65.
///
/// What a fixed vector can and cannot show. The device signed a digest chosen
/// when the vector was recorded; a Safe owner signs
/// `Sigs.nestedOwnerDigest(S_pq, clone, safeTxHash)`, which depends on the two
/// Safe addresses, the clone address, the chain id and the transaction. Those
/// are not the same 32 bytes, and no amount of test setup makes them so, since
/// that would be an EIP-712 preimage. So this test proves what holds without
/// the device's secret key:
///
///   - the device's key is accepted as a post-quantum owner, end to end:
///     the clone registers it, the lens classifies it, the policy holds;
///   - the verifier the Safe path uses accepts that device's signatures;
///   - the digest the device must be handed is computable on chain, and the
///     ERC-1271 call made with a signature over it is the one Safe performs.
///
/// Closing the loop is one device run on the digest this test prints.
contract SafePQDeviceKeyTest is SafePQFixture {
    uint256 constant K = 2;
    string constant DEVICE_VECTORS = "../lib/ETHDILITHIUM/test/KAT/ecml_device_vectors.json";

    function _device(uint256 i, string memory field) internal view returns (bytes memory) {
        return vm.parseJsonBytes(vm.readFile(DEVICE_VECTORS), string.concat(".vectors[", vm.toString(i), "].", field));
    }

    function _deviceHash(uint256 i) internal view returns (bytes32) {
        return vm.parseJsonBytes32(vm.readFile(DEVICE_VECTORS), string.concat(".vectors[", vm.toString(i), "].hash"));
    }

    /// A clone holding the device's key, as a post-quantum owner of S_pq.
    function _deviceHolder(uint256 vector, uint256 k1Pk) internal returns (PQHolder memory h) {
        h.k1Pk = k1Pk;
        h.preQKey = abi.encodePacked(vm.addr(k1Pk));
        h.postQKeyRef = _device(vector, "blob"); // publicKeyToBlob65 of the device's 1952-byte key
        assertEq(h.postQKeyRef.length, KEY_BYTES65, "device key expansion");
        h.account = pqFactory.createAccount(h.preQKey, h.postQKeyRef, 0);
        (, bytes32 postH) = h.account.keyHashes();
        assertEq(postH, keccak256(h.postQKeyRef), "the clone registers the device key");
    }

    /// The device's key is a valid post-quantum owner, and the digest it has to
    /// sign for a root transaction is computable from the chain alone.
    function test_deviceKeyAsPostQuantumOwner() public {
        PQHolder memory device = _deviceHolder(0, 0xDE71CE);
        PQHolder memory software = _pqHolder(41);
        uint256[] memory eoaPks = _eoaKeys(3, 0xA11CE);

        ISafeExec sEcdsa = _safe150(_addrs(eoaPks), K);
        PQHolder[] memory pq = new PQHolder[](2);
        pq[0] = device;
        pq[1] = software;
        ISafeExec sPq = _safe150(_pqAddrs(pq), K);
        ISafeExec root = _safe150(_pair(address(sEcdsa), address(sPq)), 2);
        vm.deal(address(root), 10 ether);

        address impl = address(pqFactory.IMPLEMENTATION());
        // a hardware key is a key: the lens sees an ordinary post-quantum owner
        assertEq(
            uint8(lens.classify(address(device.account), impl)), uint8(ZKNOX_SafePQLens.AccountKind.PQ_CLONE)
        );
        lens.requireNested(address(root), address(sEcdsa), address(sPq), K, impl);

        // what the device must be handed for this transaction
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 safeTxHash = _hash(root, t);
        bytes32 toSign = Sigs.nestedOwnerDigest(address(sPq), address(device.account), safeTxHash);
        assertEq(toSign, Sigs.pqAccountDigest(address(device.account), Sigs.safeMessageHash(address(sPq), safeTxHash)));
        assertTrue(toSign != safeTxHash, "the device signs the wrapped digest, not the safeTxHash");
        console.log("root safeTxHash", vm.toString(safeTxHash));
        console.log("digest for the device (HYBRID_SIGN_HASH)", vm.toString(toSign));
        console.log("  k1 signs the same digest; both halves go in one ERC-1271 payload");

        // the device's recorded signature is for its own digest, so it cannot
        // authorize this transaction: the account refuses it, as it should
        bytes memory wrongPayload = Sigs.hybridPayload(
            device.preQKey, _rsv(device.k1Pk, toSign), device.postQKeyRef, _device(0, "sig")
        );
        assertEq(
            device.account.isValidSignature(Sigs.safeMessageHash(address(sPq), safeTxHash), wrongPayload),
            bytes4(0xffffffff),
            "a signature over another digest must not pass"
        );
    }

    /// Every recorded device signature verifies through the ML-DSA-65 verifier
    /// the Safe path uses, with the key the clone registered.
    function test_deviceSignaturesVerifyOnTheSafeVerifier() public {
        uint256 n = vm.parseJsonUint(vm.readFile(DEVICE_VECTORS), ".count");
        assertGt(n, 0);
        for (uint256 i = 0; i < n; i++) {
            PQHolder memory device = _deviceHolder(i, 0xDE71CE + i);
            bytes memory key = device.postQKeyRef;
            bytes memory sig = _device(i, "sig");
            assertEq(sig.length, 3309, "ML-DSA-65 signature length");

            assertEq(mldsa.verify(key, _deviceHash(i), sig), ISigVerifier.verify.selector, "device signature");
            // another digest, and a flipped bit in each field of the signature
            assertTrue(mldsa.verify(key, bytes32(uint256(_deviceHash(i)) ^ 1), sig) != ISigVerifier.verify.selector);
            uint256[3] memory positions = [uint256(5), 1000, 3300]; // c~, z, h
            for (uint256 j = 0; j < 3; j++) {
                bytes memory bad = bytes.concat(sig);
                bad[positions[j]] ^= 0x01;
                assertTrue(mldsa.verify(key, _deviceHash(i), bad) != ISigVerifier.verify.selector);
            }
        }
    }
}
