#!/usr/bin/env bash
# Isolated regtest for Script verification or funded local policy measurements.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$root/src:$root${PYTHONPATH:+:$PYTHONPATH}"
profile=script
if [[ ${1:-} == --profile ]]; then
  profile=${2:?missing regtest profile}
  shift 2
fi
rpc_port=${REGTEST_RPC_PORT:-18443}
if [[ ! $rpc_port =~ ^[0-9]{1,5}$ ]] || (( 10#$rpc_port < 1 || 10#$rpc_port > 65535 )); then
  printf '%s\n' 'REGTEST_RPC_PORT must be a decimal TCP port from 1 to 65535.' >&2
  exit 2
fi
readonly rpc_port=$((10#$rpc_port))
chronicle_height=${REGTEST_CHRONICLE_HEIGHT:-2}
if [[ ! $chronicle_height =~ ^[0-9]{1,10}$ ]] || (( 10#$chronicle_height < 2 || 10#$chronicle_height > 2147483647 )); then
  printf '%s\n' 'REGTEST_CHRONICLE_HEIGHT must be a decimal block height from 2 to 2147483647.' >&2
  exit 2
fi
readonly chronicle_height=$((10#$chronicle_height))
min_mining_fee=${REGTEST_MIN_MINING_FEE:-0.000005}
if [[ ! "$min_mining_fee" =~ ^[0-9]+(\.[0-9]{1,8})?$ ]]; then
  printf '%s\n' 'REGTEST_MIN_MINING_FEE must be a nonnegative coin amount per kilobyte.' >&2
  exit 2
fi
policy=()
case "$profile" in
  script|raised)
    policy=(-maxtxsizepolicy=100000000 -maxscriptsizepolicy=100000000
            -maxstdtxvalidationduration=1000 -maxnonstdtxvalidationduration=2000)
    ;;
  long-script)
    policy=(-maxtxsizepolicy=100000000 -maxscriptsizepolicy=100000000
            -maxstdtxvalidationduration=15000 -maxnonstdtxvalidationduration=30000
            -maxtxnvalidatorasynctasksrunduration=40000)
    ;;
  default) ;;
  *) echo "Unknown regtest profile: $profile" >&2; exit 2 ;;
esac
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
"$node_bin" -regtest -server -rpcport="$rpc_port" -minminingtxfee="$min_mining_fee" -datadir="$data" \
  -listen=0 -connect=0 -dnsseed=0 -discover=0 -genesisactivationheight=1 -chronicleactivationheight="$chronicle_height" \
  -excessiveblocksize=1000000000 -maxstackmemoryusageconsensus=100000000 \
  "${policy[@]}" -printtoconsole >"$node_dir/node.log" 2>&1 &
node_pid=$!
export REGTEST_COOKIE="$data/regtest/.cookie"
export REGTEST_URL="http://127.0.0.1:$rpc_port"
export SCRIPT_LAB_REGTEST_PROFILE="$profile"
export SCRIPT_LAB_CHRONICLE_HEIGHT="$chronicle_height"
for attempt in {1..60}; do
  if ! kill -0 "$node_pid" 2>/dev/null; then tail -60 "$node_dir/node.log"; exit 1; fi
  if [[ -s "$REGTEST_COOKIE" ]] && "$cli" -regtest -rpcconnect=127.0.0.1 -rpcport="$rpc_port" -datadir="$data" getblockcount >/dev/null 2>&1; then
    if [[ ${1:-} == -- ]]; then
      shift
      "$@"
    else
      python -m unittest -v "$@"
    fi
    exit 0
  fi
  sleep 1
done
tail -60 "$node_dir/node.log"
exit 1
