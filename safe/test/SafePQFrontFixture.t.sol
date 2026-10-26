// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: SafePQFrontFixture.t.sol
// Description: writes test/fixtures/front.json, the vector the TypeScript front is checked against.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import "./SafePQFixture.sol";
import {ISafeView} from "../src/interfaces/ISafeView.sol";

/// The front (`app/packages/safe`) recomputes every digest in TypeScript rather than reading it from an
/// RPC: a signer can only check a digest the screen derived itself. That makes the TypeScript a second
/// implementation of `ZKNOX_SafePQSignatures`, and a second implementation drifts.
///
/// This test pins it. It builds the NESTED arrangement, walks the approveHash path, and writes everything
/// a signer is handed to `test/fixtures/front.json`; `app/packages/safe/test/fixture.test.ts` reproduces it
/// from the same seeds and compares. The committed JSON is what makes that test runnable without Forge —
/// regenerate it with `make safe-front-fixture` whenever a digest changes.
///
/// The 84 kB signature blob is pinned by its keccak256 and its length, not written out: the TypeScript has
/// to rebuild those bytes from the seeds to match, which checks the ML-DSA-65 key expansion, the hybrid
/// payload and the Safe packing in one comparison.
contract SafePQFrontFixtureTest is SafePQFixture {
    uint256 constant K = 2;
    uint256 constant N = 3;
    string constant OUT = "test/fixtures/front.json";

    uint256[] eoaPks;
    PQHolder[] holders;
    ISafeExec sEcdsa;
    ISafeExec sPq;
    ISafeExec root;

    function setUp() public override {
        super.setUp();
        uint256[] memory pks = _eoaKeys(N, 0xA11CE);
        PQHolder[] memory hs = _pqHolders(N, 1);
        for (uint256 i = 0; i < N; i++) {
            eoaPks.push(pks[i]);
            holders.push(hs[i]);
        }
        sEcdsa = _safe150(_addrs(pks), K);
        sPq = _safe150(_pqAddrs(hs), K);
        root = _safe150(_pair(address(sEcdsa), address(sPq)), 2);
        vm.deal(address(root), 10 ether);
    }

    function test_writeFrontFixture() public {
        Plan.SafeTx memory t = _transfer(2 ether);
        bytes32 rootHash = _hash(root, t);
        Plan.SafeTx memory approve = Plan.SafeTx({
            to: address(root),
            value: 0,
            data: abi.encodeCall(ISafeExec.approveHash, (rootHash)),
            operation: 0
        });
        bytes32 pqHash = _hash(sPq, approve);

        // the two owners that sign, and the blob their answers become
        PQHolder[] memory signers = new PQHolder[](K);
        signers[0] = holders[0];
        signers[1] = holders[1];
        bytes memory pqSigs = _pqSigs(pqHash, signers);

        Sigs.OwnerSig[] memory rs = new Sigs.OwnerSig[](2);
        rs[0] = Sigs.approved(address(sEcdsa));
        rs[1] = Sigs.approved(address(sPq));
        bytes memory rootSigs = Sigs.pack(rs);

        // and it executes: the fixture is a path that works, not a set of numbers
        _exec(sEcdsa, approve, _eoaSigs(_hash(sEcdsa, approve), _pick(eoaPks, 0, 2)));
        _exec(sPq, approve, pqSigs);
        _exec(root, t, rootSigs);
        assertEq(beneficiary.balance, 2 ether, "the approveHash path executed");

        string memory j = "front";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeUint(j, "k", K);
        vm.serializeAddress(j, "root", address(root));
        vm.serializeAddress(j, "sEcdsa", address(sEcdsa));
        vm.serializeAddress(j, "sPq", address(sPq));
        vm.serializeAddress(j, "pqImplementation", address(pqFactory.IMPLEMENTATION()));
        vm.serializeAddress(j, "lens", address(lens));
        // the root transaction, as the front would be given it
        vm.serializeAddress(j, "txTo", t.to);
        vm.serializeUint(j, "txValue", t.value);
        vm.serializeBytes(j, "txData", t.data);
        vm.serializeUint(j, "txOperation", uint256(t.operation));
        vm.serializeUint(j, "txNonce", 0);
        // the chain of digests
        vm.serializeBytes32(j, "rootSafeTxHash", rootHash);
        vm.serializeBytes32(j, "rootDomainSeparator", ISafeView(address(root)).domainSeparator());
        vm.serializeBytes32(j, "sPqDomainSeparator", ISafeView(address(sPq)).domainSeparator());
        vm.serializeBytes32(j, "sPqSafeMessageHash", Sigs.safeMessageHash(address(sPq), rootHash));
        vm.serializeBytes(j, "pqTxData", approve.data);
        vm.serializeUint(j, "pqTxNonce", 0);
        vm.serializeBytes32(j, "pqSafeTxHash", pqHash);
        // what each owner would be handed, on both paths
        vm.serializeAddress(j, "pqOwners", _pqAddrs(_holdersMem()));
        vm.serializeBytes32(j, "approveHashDigests", _digests(pqHash));
        vm.serializeBytes32(j, "nestedOwnerDigests", _nestedDigests(rootHash));
        vm.serializeString(j, "seeds", _seeds());
        vm.serializeUint(j, "k1PrivateKeys", _k1Keys());
        // the blobs
        vm.serializeBytes(j, "rootApprovedSignature", rootSigs);
        vm.serializeBytes32(j, "pqChildSignatureHash", keccak256(pqSigs));
        vm.serializeUint(j, "pqChildSignatureBytes", pqSigs.length);
        vm.serializeBytes32(j, "signerOneHybridPayloadHash", keccak256(_pqPayload(signers[0], pqHash)));
        vm.serializeUint(j, "signerOneHybridPayloadBytes", _pqPayload(signers[0], pqHash).length);
        // the figures the front puts on screen before an 84 kB transaction leaves
        bytes memory cd = abi.encodeWithSelector(
            ISafeExec.execTransaction.selector,
            approve.to, approve.value, approve.data, approve.operation,
            uint256(0), uint256(0), uint256(0), address(0), payable(address(0)), pqSigs
        );
        uint256 zeros;
        for (uint256 i = 0; i < cd.length; i++) {
            if (cd[i] == 0) zeros++;
        }
        vm.serializeUint(j, "pqExecCalldataBytes", cd.length);
        vm.serializeUint(j, "pqExecCalldataZeros", zeros);
        vm.serializeUint(j, "pqExecIntrinsic", 21000 + 4 * zeros + 16 * (cd.length - zeros));
        string memory out = vm.serializeUint(j, "pqExecFloor", 21000 + 10 * (zeros + 4 * (cd.length - zeros)));
        vm.writeJson(out, OUT);
        console.log("wrote", OUT);
    }

    function _holdersMem() internal view returns (PQHolder[] memory hs) {
        hs = new PQHolder[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            hs[i] = holders[i];
        }
    }

    /// approveHash path: one EIP-712 wrap of S_pq's own safeTxHash, per owner.
    function _digests(bytes32 pqHash) internal view returns (bytes32[] memory d) {
        d = new bytes32[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            d[i] = Sigs.pqAccountDigest(address(holders[i].account), pqHash);
        }
    }

    /// single-transaction path: the three-layer chain. Kept in the fixture because the front offers both,
    /// and handing a signer the wrong one of the two is the mistake worth a test.
    function _nestedDigests(bytes32 rootHash) internal view returns (bytes32[] memory d) {
        d = new bytes32[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            d[i] = Sigs.nestedOwnerDigest(address(sPq), address(holders[i].account), rootHash);
        }
    }

    function _seeds() internal view returns (string[] memory s) {
        s = new string[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            s[i] = holders[i].seed;
        }
    }

    function _k1Keys() internal view returns (uint256[] memory k) {
        k = new uint256[](holders.length);
        for (uint256 i = 0; i < holders.length; i++) {
            k[i] = holders[i].k1Pk;
        }
    }
}
