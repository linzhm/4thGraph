# Rust test signer for GB/T 35275-2026

[简体中文](README.zh-CN.md) · [Reference guide](../../README.md)

The Rust CLI uses RustCrypto `sm2` for SM2/SM3 signing and `der` for ASN.1
encoding. It emits a direct-signature `SignedData` envelope with outer
version `1`, inner `SignerInfo.version = 2`, and the fixed SM2 user ID
`1234567812345678`. Its fixture uses the historical issuer common name
`Independent Go Signer` and serial number `1` to preserve the DER signer
identifier shared with the [Python test signer](../python-signer/README.md).

## Build and sign a test message

Run from the repository root. The example uses a public test key.

```sh
signer_dir="$PWD/projects/p2pkh-sm2/reference/interop/rust-signer"
cargo build --locked --release --manifest-path "$signer_dir/Cargo.toml" --target-dir "$signer_dir/target"
"$signer_dir/target/release/sm2-signed-data-signer" \
  -message 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -key 0000000000000000000000000000000000000000000000000000000000000001
```

Add `-detached` to omit the message from the envelope. Standard output is a
JSON object with the fields `envelope_hex`, `public_key_hex`,
`signer_identifier_hex`, and `signer_version`. Use dedicated test keys
because the CLI takes the key as a command-line argument.

## Verify the output

Install the [reference dependencies](../../requirements.txt) and use OpenSSL
with SM2 and SM3 support. From the repository root, keep `signer_dir` as
defined above and run the Rust signer tests.

```sh
SM2_SIGNED_DATA_SIGNER="$signer_dir/target/release/sm2-signed-data-signer" \
  PYTHONPATH=src:.:projects/p2pkh-sm2/reference python -m unittest -v test_signed_data.IndependentSignedDataTests
```

Run `bash projects/p2pkh-sm2/reference/verify.sh` to build the signer
automatically and replay transactions signed by both CLIs through BSV Node
1.2.3 and chain-gang.
