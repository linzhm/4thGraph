# Chronicle regression snapshot

## Validators

The portable [dependency pin](../tools/requirements-chronicle.txt) selects chain-gang
`74676b9c002c452e7f21a9ed9265f4972bef03f6`, which includes the Chronicle context
API and complete-input OTDA fixes. The latest local comparison used an isolated
merge of the following source revisions.

| Input | Revision |
|---|---|
| Chronicle context and NOP policy | `d442b55129ac47637a5a885f7e2b448ad40d041c` |
| Chronicle OTDA | `e0ac1097913ab0a5247244fb50b39beeb57a9005` |
| Resulting Git tree | `8e3b75459ca5adbecee2e7f92e5bf8e96c1e8807` |

Both Python extensions were built offline with CPython 3.12 on macOS arm64.
The local merged wheel SHA-256 was
`d99db4c19e8a5649da9dc8b99e1c407ceb7887fd531f484e52e09692212e4b67`.
The context-only build reported `input out of tx_out range` for 16 WOTS+
cases with valid unpaired OTDA `SINGLE` spends. Those cases passed after
including the OTDA branch. The fixes remain independently identifiable.

## Complete-input checks

The matrices use explicit Chronicle activation at synthetic height 3. They
exercise spend heights 2 and 4, both transaction versions 1 and 2, older and
newer UTXOs, and different creation heights within one transaction. The
post-activation cases include unpaired OTDA `SINGLE` with `0x63` and `0xe3`.

| Project | Evidence on the local merged build |
|---|---|
| WOTS+ | 123 complete-input matrix cases and 128 explicit height, version, and sighash cases passed. The 16 existing payment vectors were reproduced. |
| ML-DSA-44 | All 640 declared payment cases matched, with 216 accepted and 424 rejected. The 60 arithmetic, 24 SHAKE, 12 signature-decoding and 22 challenge-sampling cases also passed. |
| Lamport OTS | 12 tests passed, including the existing complete-input matrix and vectors. |
| P2PKH-SM2 | Existing reference and complete-input tests passed. |
| P2PKH-R1 | 4 fixture tests passed with the script-verification call directed to the explicit chain-gang context. |

The R1 fixture replay exercises the chain-gang slice of its existing suite.
Its RPC suite requires a separate node.

## ML-DSA-44

The ML-DSA-44 verifier uses the Appendix C sampler budget of 221 bytes.
The original payment replay matched all 192 cases on both the merged
chain-gang build and `bsv-script-lean@1c051eaef1077cc95e5d1618686d5efacc4aa097`
with Lean 4.34.0.
The same chain-gang build passed the 15 external Pure ML-DSA-44 NIST ACVP
verification cases. The local wheel
used for this run had SHA-256
`df72ab485f5e46ed777ba4d212f2e0aa41b53ee42f8352abe651d5d89c5d91b0`.
Native BSV Node 1.2.3 version `101020300` matched all 192 checks through
`verifyscript` on a peerless Linux x86-64 regtest. The run completed in 36.890
seconds with `-maxscriptsizepolicy=100000000`; the default policy rejected the
926,403-byte lock before script execution.

The expanded payment fixture matched all 640 rows on the pinned chain-gang
build, native BSV Node 1.2.3, and the same Lean revision. The matrix checks every
combination of its four declared axes and verifies that no row is repeated or
omitted.
[Payment acceptance and limits](../projects/ml-dsa/reference/payment-acceptance.md)
