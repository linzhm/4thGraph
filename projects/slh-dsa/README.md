# SLH-DSA-SHA2-128s

This experiment verifies pure FIPS 205 SLH-DSA-SHA2-128s signatures with an
empty context in Bitcoin Script. It uses a 32-byte public key and a 7,856-byte
signature. The payment lock binds the signature to the spending input and
supports all twelve ForkID and Chronicle OTDA modes. Its default is `0x41`.

The [wire specification](docs/spec.md) describes the payment format. The
[Script notes](docs/script.md) record the generator provenance and costs.
The [reference vector](template/vector.json) uses a public test key and
reproduces with OpenSSL 3.5.9 and 4.1.0. Use an external signer for private keys.

## Run the checks

Use Python 3.12 and OpenSSL 3.5 or later with SLH-DSA enabled. Set
`SLH_DSA_OPENSSL` to select the executable if several versions are installed.

```sh
python -m pip install -r shared/requirements-chronicle.txt
python -m unittest discover -s projects/slh-dsa/reference -v
```

The chain-gang suite varies spend height, previous output height, transaction
version, sighash, and whether a `SINGLE` input has a corresponding output. It
also tests changes to outputs and locktime. Native BSV Node replay and mainnet
policy measurements are pending. See the [Chronicle regression snapshot](../../shared/chronicle-regression.md)
for engine revisions and test counts.
