#!/usr/bin/env bash
# Read-only RPC validation with explicit synthetic prevouts. No peers or submitted transactions.
set -euo pipefail

rpc_port=${REGTEST_RPC_PORT:-18443}
if [[ ! $rpc_port =~ ^[0-9]{1,5}$ ]] || (( 10#$rpc_port < 1 || 10#$rpc_port > 65535 )); then
  printf '%s\n' 'REGTEST_RPC_PORT must be a decimal TCP port from 1 to 65535.' >&2
  exit 2
fi
readonly rpc_port=$((10#$rpc_port))

node_dir=$(mktemp -d)
node_pid=
cleanup() {
  if [[ -n "$node_pid" ]]; then
    kill "$node_pid" 2>/dev/null || true
    wait "$node_pid" 2>/dev/null || true
  fi
  rm -rf -- "$node_dir"
}
trap cleanup EXIT

readonly archive=bitcoin-sv-1.2.3-x86_64-linux-gnu.tar.gz
readonly release=https://download.bitcoinsv.io/bitcoinsv/1.2.3
# Pin the Linux x86-64 archive listed in the v1.2.3 release SHA256SUMS.asc.
# A release upgrade must review the new archive digest with the version.
readonly expected=13f222f5b466fe4af2bb867628354e4ae9711a10019e89fc7bf018b90e30b3c8
curl -fsSL --retry 2 "$release/$archive" -o "$node_dir/$archive"
(
  cd "$node_dir"
  printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --strict -
  tar -xzf "$archive"
)
node_bin="$node_dir/bitcoin-sv-1.2.3/bin/bitcoind"
cli="$(dirname "$node_bin")/bitcoin-cli"
data="$node_dir/regtest-data"
mkdir "$data"
"$node_bin" -regtest -server -rpcport="$rpc_port" -minminingtxfee=0.000005 -datadir="$data" -listen=0 -connect=0 -dnsseed=0 -discover=0 \
  -genesisactivationheight=1 -chronicleactivationheight=2 -excessiveblocksize=1000000000 \
  -maxstackmemoryusageconsensus=100000000 -maxtxsizepolicy=100000000 -maxscriptsizepolicy=100000000 \
  -maxstdtxvalidationduration=1000 \
  -maxnonstdtxvalidationduration=2000 -printtoconsole >"$node_dir/node.log" 2>&1 &
node_pid=$!
export REGTEST_COOKIE="$data/regtest/.cookie"
export REGTEST_URL="http://127.0.0.1:$rpc_port"
for attempt in {1..60}; do
  if ! kill -0 "$node_pid" 2>/dev/null; then tail -60 "$node_dir/node.log"; exit 1; fi
  if [[ -s "$REGTEST_COOKIE" ]] && "$cli" -regtest -rpcconnect=127.0.0.1 -rpcport="$rpc_port" -datadir="$data" getblockcount >/dev/null 2>&1; then
    python -m unittest -v "$@"
    exit 0
  fi
  sleep 1
done
tail -60 "$node_dir/node.log"
exit 1
