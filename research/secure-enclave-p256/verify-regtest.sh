#!/usr/bin/env bash
# Read-only RPC validation with explicit synthetic prevouts. No peers or submitted transactions.
set -euo pipefail
node_dir=$(mktemp -d)
archive=bitcoin-sv-1.2.3-x86_64-linux-gnu.tar.gz
release=https://download.bitcoinsv.io/bitcoinsv/1.2.3
curl -fsSL --retry 2 "$release/SHA256SUMS.asc" -o "$node_dir/sums"
curl -fsSL --retry 2 "$release/$archive" -o "$node_dir/$archive"
expected=$(awk -v f="$archive" '$2==f || $2=="*" f {print $1}' "$node_dir/sums")
[[ "$expected" =~ ^[0-9A-Fa-f]{64}$ ]]
(cd "$node_dir" && echo "$expected  $archive" | sha256sum -c - && tar -xzf "$archive")
node_bin=$(find "$node_dir" -type f -name bitcoind -print -quit)
cli="$(dirname "$node_bin")/bitcoin-cli"
data="$node_dir/regtest-data"
mkdir "$data"
"$node_bin" -regtest -server -rpcport=18443 -minminingtxfee=0.000005 -datadir="$data" -listen=0 -connect=0 -dnsseed=0 -discover=0 \
  -genesisactivationheight=1 -chronicleactivationheight=2 -excessiveblocksize=1000000000 \
  -maxstackmemoryusageconsensus=100000000 -maxtxsizepolicy=100000000 -maxstdtxvalidationduration=1000 \
  -maxnonstdtxvalidationduration=2000 -daemon
trap '"$cli" -regtest -rpcport=18443 -datadir="$data" stop >/dev/null || true' EXIT
"$cli" -regtest -rpcport=18443 -datadir="$data" -rpcwait getblockcount
export REGTEST_COOKIE="$data/regtest/.cookie"
python -m unittest -v test_universal
