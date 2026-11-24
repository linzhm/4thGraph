# Chronicle regression snapshot

## Validators

The portable [dependency pin](requirements-chronicle.txt) selects chain-gang
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
| SLH-DSA-SHA2-128s | 128 height, version, and sighash cases and 64 output or locktime changes passed. Python and Script primitive tests passed. |
| ML-DSA-44 | 128 height, version, and sighash cases and 64 output or locktime changes passed. The 60 arithmetic, 24 SHAKE, 12 signature-decoding and 21 challenge-sampling cases also passed. |
| XMSS-SHA2_10_256 | 128 height, version, and sighash cases and 64 output or locktime changes passed on both the local merge and the portable pin. The 34 C-reference vectors reproduced byte for byte. |
| Lamport OTS | 12 tests passed, including the existing complete-input matrix and vectors. |
| P2PKH-SM2 | 14 reference and complete-input tests passed. |
| P2PKH-R1-Deferred | 8 tests passed, including the existing complete-input matrix. |
| P2PKH-R1 | 4 fixture tests passed with the script-verification call directed to the explicit chain-gang context. |

The R1 fixture replay exercises the chain-gang slice of its existing suite.
Its RPC suite requires a separate node. Native BSV Node and Lean results for
these new ports remain pending.
