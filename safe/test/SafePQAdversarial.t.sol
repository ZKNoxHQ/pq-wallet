// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./SafePQFixture.sol";

/// What the policy does and does not protect against.
contract SafePQAdversarialTest is SafePQFixture {
    uint256 constant K = 2;

    /// A broken post-quantum verifier (accepts anything) and an attacker holding every k1 key of the PQ side:
    /// the PQ child is fully forgeable, the root still needs K signatures of the ECDSA child.
    function test_brokenPQVerifier_securityFallsBackToEcdsaSide() public {
        AcceptAllVerifier broken = new AcceptAllVerifier();
        ZKNOX_PQFactory7702 brokenFactory = new ZKNOX_PQFactory7702(entryPoint, k1, broken, "broken");
        PQHolder[] memory forged = new PQHolder[](2);
        for (uint256 i = 0; i < 2; i++) {
            forged[i].k1Pk = 0xBAD0 + i;
            forged[i].preQKey = abi.encodePacked(vm.addr(forged[i].k1Pk));
            forged[i].postQKeyRef = hex"00"; // AcceptAllVerifier.setKey is the identity
            forged[i].account = brokenFactory.createAccount(forged[i].preQKey, forged[i].postQKeyRef, 0);
        }
        uint256[] memory eoaPks = _eoaKeys(3, 0xA11CE);
        ISafeExec sEcdsa = _safe150(_addrs(eoaPks), K);
        ISafeExec sPq = _safe150(_pqAddrs(forged), K);
        ISafeExec root = _safe150(_pair(address(sEcdsa), address(sPq)), 2);
        vm.deal(address(root), 1 ether);

        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(root, t);
        bytes32 mP = Sigs.safeMessageHash(address(sPq), h);
        Sigs.OwnerSig[] memory pq = new Sigs.OwnerSig[](2);
        for (uint256 i = 0; i < 2; i++) {
            bytes32 d = Sigs.pqAccountDigest(address(forged[i].account), mP);
            pq[i] = Sigs.contractSig(
                address(forged[i].account),
                Sigs.hybridPayload(forged[i].preQKey, _rsv(forged[i].k1Pk, d), forged[i].postQKeyRef, hex"deadbeef")
            );
        }
        bytes memory forgedPqSig = Sigs.pack(pq);

        // forged PQ side + one stolen ECDSA key: rejected
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), h), _one(eoaPks[0])));
        s[1] = Sigs.contractSig(address(sPq), forgedPqSig);
        vm.expectRevert();
        _exec(root, t, Sigs.pack(s));

        // forged PQ side alone: rejected
        Sigs.OwnerSig[] memory only = new Sigs.OwnerSig[](1);
        only[0] = Sigs.contractSig(address(sPq), forgedPqSig);
        vm.expectRevert();
        _exec(root, t, Sigs.pack(only));

        // K honest ECDSA signatures: accepted, i.e. exactly the classical K-of-n baseline
        s[0] =
            Sigs.contractSig(address(sEcdsa), _eoaSigs(Sigs.safeMessageHash(address(sEcdsa), h), _pick(eoaPks, 0, 1)));
        _exec(root, t, Sigs.pack(s));
        assertEq(beneficiary.balance, 1 ether);

        // the lens pins the audited implementation: clones of another verifier pair are not PQ owners
        uint256 v =
            lens.nestedViolations(address(root), address(sEcdsa), address(sPq), K, address(pqFactory.IMPLEMENTATION()));
        assertEq(v, lens.CHILD_OWNERS() << lens.PQ_SHIFT());
    }

    /// An EOA delegated to ZKNOX_PQAccount7702 (EIP-7702) as a PQ owner: its ECDSA key alone satisfies the
    /// ecrecover branch of checkNSignatures, no ML-DSA signature is ever checked. The lens refuses it.
    function test_7702DelegatedOwner_bypassesPQ() public {
        uint256 eoaPk = 0x7702;
        address eoa = vm.addr(eoaPk);
        PQHolder memory h1 = _pqHolder(1);
        bytes memory expandedKey = _mldsa65("key", _seed(7), "");
        vm.attachDelegation(vm.signDelegation(address(pqFactory.IMPLEMENTATION()), eoaPk));
        vm.prank(eoa);
        ZKNOX_PQAccount7702(payable(eoa)).initialize(abi.encodePacked(eoa), expandedKey);
        assertEq(
            uint8(lens.classify(eoa, address(pqFactory.IMPLEMENTATION()))),
            uint8(ZKNOX_SafePQLens.AccountKind.DELEGATED_7702)
        );

        address[] memory owners = _pair(eoa, address(h1.account));
        ISafeExec sPq = _safe150(owners, 2);
        vm.deal(address(sPq), 1 ether);
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(sPq, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.ecdsa(eoa, _rsv(eoaPk, h)); // plain ECDSA, v = 27/28
        s[1] = Sigs.contractSig(address(h1.account), _pqPayload(h1, h));
        _exec(sPq, t, Sigs.pack(s));
        assertEq(beneficiary.balance, 1 ether, "7702 owner signed with ECDSA only");
    }

    /// Safe 1.4.1 calls the legacy isValidSignature(bytes,bytes): a PQ clone cannot be one of its owners.
    function test_safe141_rejectsPQOwner() public {
        PQHolder memory h1 = _pqHolder(1);
        uint256[] memory eoaPks = _eoaKeys(1, 0xA11CE);
        ISafeExec safe = _safe(singleton141, _pair(vm.addr(eoaPks[0]), address(h1.account)), 2, handler141);
        vm.deal(address(safe), 1 ether);
        Plan.SafeTx memory t = _transfer(1 ether);
        bytes32 h = _hash(safe, t);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](2);
        s[0] = Sigs.ecdsa(vm.addr(eoaPks[0]), _rsv(eoaPks[0], h));
        s[1] = Sigs.contractSig(address(h1.account), _pqPayload(h1, h));
        vm.expectRevert();
        _exec(safe, t, Sigs.pack(s));
        assertEq(beneficiary.balance, 0);
    }

    /// Packing: ascending owners, contract payloads appended with offsets past the static part.
    function test_pack_layout() public pure {
        address a = address(0x10);
        address b = address(0x20);
        address c = address(0x30);
        Sigs.OwnerSig[] memory s = new Sigs.OwnerSig[](3);
        s[0] = Sigs.contractSig(c, hex"aabbcc");
        s[1] = Sigs.approved(b);
        s[2] = Sigs.contractSig(a, hex"11");
        bytes memory out = Sigs.pack(s);
        assertEq(out.length, 65 * 3 + 32 + 1 + 32 + 3);
        bytes memory expected = bytes.concat(
            bytes32(uint256(uint160(a))),
            bytes32(uint256(195)),
            hex"00",
            bytes32(uint256(uint160(b))),
            bytes32(0),
            hex"01",
            bytes32(uint256(uint160(c))),
            bytes32(uint256(195 + 33)),
            hex"00",
            bytes32(uint256(1)),
            hex"11",
            bytes32(uint256(3)),
            hex"aabbcc"
        );
        assertEq(out, expected);
    }
}
