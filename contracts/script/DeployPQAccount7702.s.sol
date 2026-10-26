// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {EntryPoint} from "account-abstraction/contracts/core/EntryPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";
import {ECDSAk1Verifier} from "InterfaceVerifier/VerifierECDSAk1.sol";
import {ZKNOX_dilithium} from "ETHDILITHIUM/src/ZKNOX_dilithium.sol";
import {ZKNOX_falcon8_verifier} from "../src/ZKNOX_falcon8_verifier.sol";
import {ZKNOX_PQFactory7702} from "../src/ZKNOX_PQFactory7702.sol";
import {ZKNOX_PQSatellite7702} from "../src/ZKNOX_PQSatellite7702.sol";
import {TestToken} from "../src/TestToken.sol";

/// Deploys, for one chain:
///   - two Keccak-f[1600] helpers: Fireblocks (../lib/ETHDILITHIUM/test/f1600_170.hex) for ML-DSA and
///     ETHFALCON's own (../lib/ETHFALCON/test/f1600_zknox.hex) for Falcon, unless F1600_HELPER / F1600_ZKNOX_HELPER are set
///   - the k1 verifier, the ML-DSA-44 verifier, the Falcon-512 eight-lane verifier
///   - one factory (vault implementation + clones) per post-quantum scheme
///   - the satellite (EIP-7702 delegate of the EOAs linked to a vault), scheme-independent
/// Writes contracts/deployments/<chainId>.json (consumed by app/packages/core).
/// Env: ENTRY_POINT (default: canonical EntryPoint v0.8, deployed locally if that address has no code),
///      F1600_HELPER (optional), VERSION (default "0.1.0")
contract DeployPQAccount7702 is Script {
    address constant ENTRY_POINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    function run() external {
        IEntryPoint entryPoint = IEntryPoint(vm.envOr("ENTRY_POINT", ENTRY_POINT_V08));
        string memory version = vm.envOr("VERSION", string("0.1.0"));
        address helper = vm.envOr("F1600_HELPER", address(0));
        address zknoxHelper = vm.envOr("F1600_ZKNOX_HELPER", address(0));

        vm.startBroadcast();
        if (address(entryPoint).code.length == 0) {
            // local chain (anvil): no canonical EntryPoint, deploy one
            entryPoint = new EntryPoint();
        }
        if (helper == address(0)) {
            helper = _deployHelper("../lib/ETHDILITHIUM/test/f1600_170.hex");
        }
        if (zknoxHelper == address(0)) {
            zknoxHelper = _deployHelper("../lib/ETHFALCON/test/f1600_zknox.hex");
        }
        ISigVerifier k1 = new ECDSAk1Verifier();
        ISigVerifier mldsa = new ZKNOX_dilithium(helper);
        ISigVerifier falcon = new ZKNOX_falcon8_verifier(zknoxHelper);
        ZKNOX_PQFactory7702 factoryMLDSA = new ZKNOX_PQFactory7702(entryPoint, k1, mldsa, version);
        ZKNOX_PQFactory7702 factoryFalcon = new ZKNOX_PQFactory7702(entryPoint, k1, falcon, version);
        ZKNOX_PQSatellite7702 satellite = new ZKNOX_PQSatellite7702(entryPoint);
        // a mintable token on local chains and testnets, so the app can show and sweep an ERC-20
        address testToken = address(0);
        if (block.chainid != 1 && block.chainid != 42161) {
            testToken = address(new TestToken());
        }
        vm.stopBroadcast();

        console.log("f1600 helper (ML-DSA)  ", helper);
        console.log("f1600 helper (Falcon)  ", zknoxHelper);
        console.log("ECDSAk1Verifier        ", address(k1));
        console.log("ZKNOX_dilithium        ", address(mldsa));
        console.log("ZKNOX_falcon8_verifier ", address(falcon));
        console.log("factory k1+MLDSA       ", address(factoryMLDSA));
        console.log("  delegate k1+MLDSA    ", address(factoryMLDSA.IMPLEMENTATION()));
        console.log("factory k1+FALCON      ", address(factoryFalcon));
        console.log("  delegate k1+FALCON   ", address(factoryFalcon.IMPLEMENTATION()));
        console.log("satellite (EOA delegate)", address(satellite));

        string memory j = "deployments";
        vm.serializeUint(j, "chainId", block.chainid);
        vm.serializeUint(j, "startBlock", block.number);
        vm.serializeAddress(j, "entryPoint", address(entryPoint));
        vm.serializeAddress(j, "f1600Helper", helper);
        vm.serializeAddress(j, "f1600ZknoxHelper", zknoxHelper);
        vm.serializeAddress(j, "ecdsaK1Verifier", address(k1));
        vm.serializeAddress(j, "mldsaVerifier", address(mldsa));
        vm.serializeAddress(j, "falconVerifier", address(falcon));
        vm.serializeAddress(j, "factoryMLDSA", address(factoryMLDSA));
        vm.serializeAddress(j, "delegateMLDSA", address(factoryMLDSA.IMPLEMENTATION()));
        vm.serializeAddress(j, "factoryFalcon", address(factoryFalcon));
        vm.serializeAddress(j, "delegateFalcon", address(factoryFalcon.IMPLEMENTATION()));
        vm.serializeAddress(j, "satellite", address(satellite));
        string memory out = vm.serializeAddress(j, "testToken", testToken);
        vm.writeJson(out, string.concat("deployments/", vm.toString(block.chainid), ".json"));
    }

    function _deployHelper(string memory path) internal returns (address helper) {
        bytes memory runtime = vm.parseBytes(vm.readFile(path));
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "helper: CREATE failed");
    }
}
