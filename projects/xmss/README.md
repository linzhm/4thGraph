# XMSS-SHA2_10_256

This experiment uses a single RFC 8391 XMSS tree to authorize BSV payments.
Its public key is 68 bytes, its raw signature is 2,500 bytes, and the tree has
1,024 one-time signing indices. The verifier reconstructs the signed WOTS+
leaf and the XMSS root in Script. The payment wrapper binds the signature to
the current input and defaults to ForkID `ALL` (`0x41`).

The [wire specification](docs/spec.md) describes the encoding and signer
state. The [vectors](template/vectors.json) use a public test seed and include
32 complete payments, plus detached signatures at indices 0 and 1,022.

## Check the implementation

From the repository root, run the Python reference and Script tests first.
Use the explicit Chronicle-context build for the full transaction checks.

```sh
python -m unittest discover -s projects/xmss/reference -p test_xmss.py -v
python -m pip install -r shared/requirements-chronicle.txt
python -m unittest discover -s projects/xmss/reference -p test_chronicle.py -v
```

The transaction matrix covers all 12 ForkID and OTDA combinations, paired and
unpaired `SINGLE`, transaction versions 1 and 2, and UTXO creation and spending
on both sides of Chronicle activation. It also checks output and locktime
commitments. [Chronicle regression record](../../shared/chronicle-regression.md)

The `0x41` fixture uses a 55,691-byte locking script and a 2,669-byte
unlocking script. BSV Node and Lean conformance runs are pending.

## Regenerate the public vectors

Use [XMSS/xmss-reference at `171ccbd`](https://github.com/XMSS/xmss-reference/tree/171ccbd26f098542a67eb5d2b128281c80bd71a6)
and OpenSSL development headers. Set `xmss_source` to that checkout and
`xmss_oracle` to the path for the temporary executable.

```bash
cc -O3 -I "$xmss_source" $(pkg-config --cflags openssl) \
  projects/xmss/reference/oracle.c \
  "$xmss_source"/{xmss,xmss_core,xmss_commons,params,hash,hash_address,utils,wots,fips202}.c \
  $(pkg-config --libs openssl) -o "$xmss_oracle"
python projects/xmss/reference/fixtures.py "$xmss_oracle" > /tmp/xmss-vectors.json
cmp /tmp/xmss-vectors.json projects/xmss/template/vectors.json
```

The C oracle verifies each signature before exporting it. The vector generator
also checks the original message and signature with the Python verifier.
