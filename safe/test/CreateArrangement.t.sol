// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: CreateArrangement.t.sol
// Description: the two claims CreateArrangement rests on — a predicted proxy address, and resumability.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SafePQFixture} from "./SafePQFixture.sol";
import {CreateArrangement} from "../script/CreateArrangement.s.sol";
import {ISafeProxyFactory, ISafeView} from "../src/interfaces/ISafeView.sol";

// The fixture declares its own Safe interfaces inline, so its `proxyFactory` is a different type from the
// one the script uses. This suite keeps its own fields rather than borrowing the fixture's.

/// Reaches the script's internals from a test without inheriting both `Script` and `Test`.
contract ArrangementProbe is CreateArrangement {
    /// `proxies` is taken as an address: the fixture and the script reach `ISafeProxyFactory` through
    /// different import paths, and Solidity treats those as two types.
    function safe(
        address proxies,
        address singleton,
        address[] memory owners,
        uint256 threshold,
        uint256 saltNonce
    ) external returns (address, bool) {
        return _safe(ISafeProxyFactory(proxies), singleton, owners, threshold, saltNonce, "S");
    }
}

/// `CreateArrangement` promises that a run which dies between two transactions can be run again. That rests
/// on two things, neither obvious enough to take on trust: the CREATE2 address of a Safe proxy is
/// recomputed in the script rather than read back from the factory, and the salt comes from the owner set
/// instead of a timestamp. Get the first wrong and the script reverts on every arrangement; get the second
/// wrong and a resumed run silently builds a second arrangement beside the half-finished one.
contract CreateArrangementTest is SafePQFixture {
    ArrangementProbe internal probe;

    /// Deliberately NOT `super.setUp()`. Nothing here needs the ML-DSA stack, and the full fixture deploys
    /// it — the f1600 helper through `vm.ffi` included — once per test. Six of those alongside the rest of
    /// the suite under `forge test -j` was enough to make other suites' `vm.ffi` calls fail to spawn.
    /// `SafePQFixture` is still the parent, for its artifact resolver: two Safe releases share file and
    /// contract names and only it knows how Forge disambiguates them.
    address internal safe150;
    address internal proxies;

    function setUp() public override {
        safe150 = deployCode(_artifact(S150, "Safe.sol", "Safe"));
        proxies = deployCode(_artifact(S150, "proxies/SafeProxyFactory.sol", "SafeProxyFactory"));
        address fallbackHandler =
            deployCode(_artifact(S150, "handler/CompatibilityFallbackHandler.sol", "CompatibilityFallbackHandler"));
        // `_safe` reads the canonical handler through the script base, which takes it from the environment
        // when one is set — the mechanism `SafePQScripts.t.sol` already uses to point the scripts at a
        // locally deployed Safe stack.
        vm.setEnv("FALLBACK_HANDLER_150", vm.toString(fallbackHandler));
        probe = new ArrangementProbe();
    }

    function _owners(uint256 n, uint256 tag) internal pure returns (address[] memory out) {
        out = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = address(uint160(uint256(keccak256(abi.encodePacked("owner", tag, i)))));
        }
    }

    function test_the_predicted_address_is_where_the_proxy_lands() public {
        address[] memory owners = _owners(3, 1);
        (address safe, bool created) = probe.safe(proxies, safe150, owners, 2, 0);
        assertTrue(created, "the first run should create");
        assertGt(safe.code.length, 0, "no code at the predicted address");
        assertEq(ISafeView(safe).getThreshold(), 2);
        assertEq(ISafeView(safe).getOwners().length, 3);
        assertEq(ISafeView(safe).VERSION(), "1.5.0");
    }

    function test_a_second_run_reuses_instead_of_creating_a_twin() public {
        address[] memory owners = _owners(3, 2);
        (address first, bool created) = probe.safe(proxies, safe150, owners, 2, 0);
        (address again, bool createdAgain) = probe.safe(proxies, safe150, owners, 2, 0);
        assertEq(again, first, "a resumed run must land on the same Safe");
        assertTrue(created);
        assertFalse(createdAgain, "the second run must not create anything");
    }

    function test_the_salt_follows_the_owner_set() public {
        address[] memory a = _owners(3, 3);
        address[] memory b = _owners(3, 4);
        (address sa,) = probe.safe(proxies, safe150, a, 2, 0);
        (address sb,) = probe.safe(proxies, safe150, b, 2, 0);
        assertTrue(sa != sb, "different owners, different Safe");

        // Same owners, different threshold: also a different Safe. The threshold is in the salt and in the
        // initializer both, so S_ecdsa and S_pq of one arrangement can never collide either.
        (address sc,) = probe.safe(proxies, safe150, a, 3, 0);
        assertTrue(sc != sa, "a different threshold must not land on an existing Safe");

        // and the escape hatch, for an operator who wants a second arrangement over the same owners
        (address sd,) = probe.safe(proxies, safe150, a, 2, 1);
        assertTrue(sd != sa, "SALT_NONCE must move the address");
    }

    function test_time_does_not_move_the_address() public {
        address[] memory owners = _owners(3, 5);
        (address before_,) = probe.safe(proxies, safe150, owners, 2, 0);
        vm.warp(block.timestamp + 7 days);
        vm.roll(block.number + 50_000);
        (address after_, bool created) = probe.safe(proxies, safe150, owners, 2, 0);
        assertEq(after_, before_, "the address must not depend on the clock");
        assertFalse(created);
    }

    function test_the_order_of_owners_is_part_of_the_identity() public {
        address[] memory a = _owners(3, 6);
        address[] memory reversed = new address[](3);
        for (uint256 i = 0; i < 3; i++) reversed[i] = a[2 - i];
        (address sa,) = probe.safe(proxies, safe150, a, 2, 0);
        (address sr,) = probe.safe(proxies, safe150, reversed, 2, 0);
        // Safe stores owners in a linked list, so the two Safes are equivalent; the addresses differ, which
        // is worth knowing before an operator reorders ECDSA_OWNERS between two runs and wonders why the
        // script built a new arrangement.
        assertTrue(sa != sr, "reordering the owners yields another Safe");
        assertEq(ISafeView(sa).getOwners().length, ISafeView(sr).getOwners().length);
    }
}
