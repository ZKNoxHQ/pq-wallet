#!/usr/bin/env bash
# One-time setup of pq-wallet: the pinned dependencies, the reference signers, the app workspace.
#
# Everything under lib/ is a git submodule pinned by commit, the ZKNOX ones on their experimental
# branches: ETHDILITHIUM on mldsa65-calldata (ML-DSA in the calldata), ETHFALCON on
# exp/pq-verifier-gas. A pin moves by checking the submodule out and committing it, never by a
# branch name, so a clone of this repository builds the same bytecode a year from now.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== submodules"
git submodule update --init --recursive
git submodule foreach --quiet 'printf "%-26s %s\n" "$name" "$(git rev-parse --short HEAD)"'

# The reference signers the Forge tests drive through vm.ffi. ETHDILITHIUM's python one produces the
# ML-DSA-44 keys and signatures of contracts/, its js one the ML-DSA-65 of safe/ (scripts/mldsa65.mjs).
echo "== reference signers"
[ -x lib/ETHDILITHIUM/pythonref/myenv/bin/python ] || make -C lib/ETHDILITHIUM/pythonref install
[ -x lib/ETHFALCON/pythonref/myenv/bin/python ] || make -C lib/ETHFALCON/pythonref install
[ -d lib/ETHDILITHIUM/js/node_modules ] || (cd lib/ETHDILITHIUM/js && npm install --no-audit --no-fund)

echo "== app workspace"
(cd app && pnpm install)

echo
echo "done -- make test"
