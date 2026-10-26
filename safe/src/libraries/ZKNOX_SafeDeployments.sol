// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_SafeDeployments.sol
// Description: canonical Safe addresses (safe-global/safe-deployments, "canonical" entries), identical on
//              every chain where the Safe singleton factory is deployed. Scripts check the code is present.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library ZKNOX_SafeDeployments {
    // ---- v1.5.0
    address internal constant SAFE_150 = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b;
    address internal constant SAFE_L2_150 = 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e;
    address internal constant PROXY_FACTORY_150 = 0x14F2982D601c9458F93bd70B218933A6f8165e7b;
    address internal constant COMPATIBILITY_FALLBACK_HANDLER_150 = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;
    address internal constant SAFE_MIGRATION_150 = 0x6439e7ABD8Bb915A5263094784C5CF561c4172AC;
    address internal constant MULTI_SEND_CALL_ONLY_150 = 0xA83c336B20401Af773B6219BA5027174338D1836;

    // ---- singletons that SafeMigration 1.5.0 can migrate from (L1 / L2)
    address internal constant SAFE_141 = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant SAFE_L2_141 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address internal constant SAFE_130 = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address internal constant SAFE_130_EIP155 = 0x69f4D1788e39c87893C980c06EdF4b7f686e2938;
    address internal constant SAFE_L2_130 = 0x3E5c63644E683549055b9Be8653de26E0B4CD36E;
    address internal constant SAFE_L2_130_EIP155 = 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA;

    function isKnownL2Singleton(address singleton) internal pure returns (bool) {
        return singleton == SAFE_L2_150 || singleton == SAFE_L2_141 || singleton == SAFE_L2_130
            || singleton == SAFE_L2_130_EIP155;
    }

    function isKnownL1Singleton(address singleton) internal pure returns (bool) {
        return singleton == SAFE_150 || singleton == SAFE_141 || singleton == SAFE_130 || singleton == SAFE_130_EIP155;
    }
}
