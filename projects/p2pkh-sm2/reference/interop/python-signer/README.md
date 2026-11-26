# Python test signer for GB/T 35275-2026

[简体中文](README.zh-CN.md) · [Reference guide](../../README.md)

The Python CLI uses OpenSSL 3 with SM2 and SM3 support for signing and
`asn1crypto` to encode the result as DER. It emits a direct-signature
`SignedData` envelope with outer version `1`, inner `SignerInfo.version = 2`,
and the fixed SM2 user ID `1234567812345678`. The CLI arguments, JSON fields,
and DER signer identifier also work with the [Rust test signer](../rust-signer/README.md).

## Sign a test message

Run from this directory with Python 3.12 or later. The example uses a public
test key.

```sh
python3 -m pip install asn1crypto==1.5.1
python3 sm2_signed_data_signer.py \
  -message 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -key 0000000000000000000000000000000000000000000000000000000000000001
```

Add `-detached` to omit the message from the envelope. Standard output is a
JSON object with the fields `envelope_hex`, `public_key_hex`,
`signer_identifier_hex`, and `signer_version`.

Use dedicated test keys. The CLI passes the key on the command line and
writes it to a private temporary directory for OpenSSL. Python removes the
directory when signing finishes.

## Verify the output

From the repository root, install the [reference dependencies](../../requirements.txt)
and run the Python signer tests.

```sh
PYTHONPATH=src:.:projects/p2pkh-sm2/reference \
  python -m unittest -v test_signed_data.PythonSignedDataSignerTests
```

Run `bash projects/p2pkh-sm2/reference/verify.sh` to replay transactions
signed by both CLIs through BSV Node 1.2.3 and chain-gang.
