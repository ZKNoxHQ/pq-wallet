// SPDX-License-Identifier: MIT
// Pulls the Safe 1.5.0 and 1.4.1 contracts into the build (legacy pipeline, see foundry.toml) so the tests can
// deploy them from their artifacts. Nothing else imports Safe sources.
pragma solidity >=0.7.0 <0.9.0;

import "safe/Safe.sol";
import "safe/SafeL2.sol";
import "safe/proxies/SafeProxyFactory.sol";
import "safe/handler/CompatibilityFallbackHandler.sol";
import "safe/libraries/MultiSendCallOnly.sol";
import "safe/libraries/SafeMigration.sol";
