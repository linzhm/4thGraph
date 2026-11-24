# WOTS+ validation record

| Check | Result |
|---|---|
| Python and development Script tests | 7 passed, including all 67 signature-chain mutations, concurrent signer use and 16 deterministic payment vectors |
| Independent XMSS C reference | Public endpoint commitment and four complete signatures matched revision `171ccbd26f098542a67eb5d2b128281c80bd71a6`, built against OpenSSL |
| chain-gang complete inputs | All 123 outcomes matched at revision `5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7`, covering all 12 modes, unpaired `SINGLE` and malformed witnesses |
| Existing templates | All 12 Lamport regression tests and both repository layout tests passed, including existing signature vectors and canonical R1 bytes |
| BSV Node 1.2.3 | Native verdicts pending. Apple Container launch was denied by the local runner, and the Linux release host was unreachable |
| bsv-script-lean | The complete-input adapter serialized 125 fixtures, including two pre-Chronicle spends. Lean verdicts pending because the evaluator and its pinned Lean 4.34.0/Mathlib toolchain were unavailable |

## ForkID `ALL` measurements

Both measurements used a single-input, single-output synthetic payment. Lock
and unlock columns are Script bytes, excluding transaction wire overhead. The
timings are the median of 30 warm complete-transaction checks in the same
chain-gang build on macOS arm64 with Python 3.12.

| Template | Raw signature | Lock | Unlock | Lock + unlock | Chain-gang |
|---|---:|---:|---:|---:|---:|
| Lamport OTS | 8,192 B | 22,780 B | 8,357 B | 31,137 B | 0.289 ms |
| WOTS+ | 2,144 B | 42,266 B | 2,310 B | 44,576 B | 1.028 ms |

WOTS+ saves 6,047 bytes on the spend's unlocking script. This implementation
adds 19,486 bytes to the funding lock, largely because the Script unrolls the
keyed and masked chain steps. Across both scripts it adds 13,439 bytes, or 43%.

Run the suites and regenerate the vectors using the
[project README](../README.md#run-the-checks) and `reference/fixtures.py`.

The [Chronicle regression snapshot](../../../shared/chronicle-regression.md)
records the later checks with updated context and OTDA revisions. Those
checks exercised 251 complete inputs with explicit activation and creation
heights and preserved the existing vectors.
