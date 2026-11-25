#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z ${SM2_SIGNED_DATA_SIGNER:-} ]]; then
  signer="$PWD/interop/rust-signer"
  cargo build --locked --release --manifest-path "$signer/Cargo.toml" --target-dir "$signer/target"
  export SM2_SIGNED_DATA_SIGNER="$signer/target/release/sm2-signed-data-signer"
fi
exec bash ../../../shared/verify_node.sh test_sighash test_node test_otda_constructor test_signed_data test_signed_data_acceptance
