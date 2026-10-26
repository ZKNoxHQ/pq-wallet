CORES := $(shell nproc)
ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC := http://127.0.0.1:8545

# One-time setup: submodules at their pinned commits, reference signers, app workspace.
install:
	./scripts/bootstrap.sh

# ---- everything
test: test-contracts test-safe test-app
build: build-contracts build-safe

# ---- contracts: the hybrid account, its satellite, the factory
build-contracts:
	cd contracts && forge build --sizes
test-contracts:
	cd contracts && forge test -j$(CORES) -vv
test-contracts-fast:
	cd contracts && forge test --match-contract MLDSA -vv

# ---- safe: post-quantum owners of a Safe
build-safe:
	cd safe && forge build --sizes
test-safe:
	cd safe && forge test -j$(CORES) -vv --no-match-contract SafePQFrontFixtureTest
test-safe-gas:
	cd safe && forge test --match-test "test_nested_exec_2ecdsa_2pq|test_nested_approveHash_path" -vv
# the vector app/packages/safe is checked against: regenerate it whenever a digest changes
safe-front-fixture:
	cd safe && forge test --match-contract SafePQFrontFixtureTest -vv

# ---- app: the wallet core, its UI, the demo, the Safe signer
test-app:
	cd app && pnpm -r test
dev:
	cd app && pnpm dev
# the front that collects post-quantum owner signatures for a Safe (http://localhost:5174).
# Served alongside it, /host.html frames the app the way Safe{Wallet} does, for the hosted path.
safe-signer:
	cd app && pnpm --filter safe-signer dev
build-app:
	cd app/apps/demo && pnpm exec vite build
	cd app/apps/safe-signer && pnpm exec vite build
abi: build-contracts
	cd app && pnpm abi

# ---- local chain
anvil:
	anvil --port 8545
deploy-local:
	cd contracts && forge script script/DeployPQAccount7702.s.sol --rpc-url $(RPC) --private-key $(ANVIL_KEY) --broadcast
	cd app && pnpm abi
e2e: deploy-local
	cd app/packages/core && pnpm exec vitest run test/e2e.anvil.test.ts
# The whole NESTED arrangement on anvil — Safe singletons included — for the safe-signer front.
# --gas-estimate-multiplier: a clone is created with its 38 kB expanded key in the calldata, and forge
# records the simulated call's gas, which does not include the transaction's own intrinsic calldata cost.
# The resulting limit is below the intrinsic cost, so the node accepts the transaction and can never mine
# it: the script hangs on a receipt that will not come.
safe-deploy-local:
	cd safe && forge script script/DeployLocalNested.s.sol --rpc-url $(RPC) --broadcast --slow \
	  --gas-estimate-multiplier 300

# ---- public networks (SEPOLIA_RPC and DEPLOYER_KEY from the environment)
deploy-sepolia:
	cd contracts && forge script script/DeployPQAccount7702.s.sol --rpc-url $(SEPOLIA_RPC) --private-key $(DEPLOYER_KEY) --broadcast
	cd app && pnpm abi

# ---- Safe scripts on a live chain (RPC, and the variables each script's header documents)
safe-inspect:
	cd safe && forge script script/InspectSafe.s.sol --rpc-url $(RPC)
safe-plan:
	cd safe && forge script script/PlanNestedMigration.s.sol --rpc-url $(RPC)
safe-digest:
	cd safe && forge script script/PqOwnerDigest.s.sol --rpc-url $(RPC)
safe-deploy-lens:
	cd safe && forge script script/DeployLens.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast
# the ML-DSA-65 account stack on a chain that already has Safe 1.5.0 (Sepolia, mainnet)
safe-deploy-pq65:
	cd safe && forge script script/DeployPqStack65.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast
# one post-quantum owner, from the keys a device reported (FACTORY, K1_ADDRESS, KEY_FILE)
safe-create-owner:
	cd safe && forge script script/CreatePqOwner.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast \
	  --gas-estimate-multiplier 300
# the 2-of-2 root owning the two children (S_ECDSA, S_PQ, K)
safe-create-root:
	cd safe && forge script script/CreateRootSafe.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast
safe-deploy-children:
	cd safe && forge script script/DeployNestedSafes.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast
safe-exec-planned:
	cd safe && forge script script/ExecPlannedTx.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast
safe-exec-nested:
	cd safe && forge script script/ExecNestedTx.s.sol --rpc-url $(RPC) --ledger --sender $(SENDER) --broadcast

.PHONY: install test build test-contracts test-safe test-app dev safe-signer abi anvil \
        safe-front-fixture safe-deploy-local safe-deploy-pq65 safe-create-owner safe-create-root
