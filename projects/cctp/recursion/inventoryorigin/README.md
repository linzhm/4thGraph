# Bounded inventory source certificate

This test profile translates an independently approved list of four distinct token leaves into a reusable binary Merkle root. Each leaf commits to the asset scope, exact wire outpoint, token quantity, satoshis, compressed owner and frozen flag. The issuance or transition validator approves the actual source leaves before this component is used. An inventory proof alone supplies no authority to approve an arbitrary list or to roll a recipient's new outputs into an approved list.

The caller fixes the approved anchor in the executing verifier or an authenticated funding ticket. With SHA256d denoted by H, the anchor is `H(0x04 || leaf[0] || ... || leaf[3])`. The private witness has these 128 bytes and a four-byte permutation. The circuit checks each source index is in range and used exactly once. It computes each Merkle parent with `H(0x01 || left || right)`. The two big-endian uint128 public limbs encode `H(0x03 || approved_anchor || inventory_root)`. The verifier key is independent of the chosen anchor, so creating new origin outpoints has no key–txid dependency.

For a fixed order, [the 69-byte direct Script](../inventory_origin.py) verifies the same approved list and recomputes the Merkle root without proving. Its two standalone witness pushes take 163 bytes, including the root. A full payment also binds the selected leaf openings and the actual outputs, and authorizes the real inputs. Funding creation and complete scripts are measured by the payment driver.

The [four archived origins](../../fixtures/inventory-origin-v3-archive.json) are already spent outputs from four different v3 Token transactions. The extractor loads the independent node, checks their creation with the existing certified wallet relation, rejects their receipt vouts, and verifies the old four-parent aggregate under the expected continuity key. The old aggregate authenticates ordered predecessor statements. The node and the certified wallet independently bind actual balances to the selected vouts. The [test source proof](../../fixtures/inventory-origin-v3-proof.json) uses the externally approved leaf hashes from this run. This separate step does not place the old full-node relation in the translation circuit.

The archive experiment compiled 545,181 constraints. Native proving took 4.553 s and native verification 1.89 ms. The cold process took 116.07 s including recompilation and checked key loading, with a maximum resident set of 1,280,507,904 bytes during simultaneous local runs. This proof contributes 1,078 bytes of proof fields to the projective witness. The generic verifier lock is 449,730 bytes before composing with the payment rules. An independent read of the stored verification key reproduced Script acceptance and rejected a changed public limb.

Reproduce from the worktree root with the original regtest and its archived prover outputs:

```sh
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  ../cctp-test-tools/venv/bin/python projects/cctp/recursion/inventory_origin_archive.py \
  --node-url "$REGTEST_URL" --cookie "$REGTEST_COOKIE" --archive "$OLD_64_ARCHIVE" \
  --old-key "$OLD_CONTINUITY_SETUP/key.json" --out "$NEW_REPORT"
go -C projects/cctp/recursion test ./inventoryorigin
go -C projects/cctp/recursion build -o "$PROBE" ./freeze/cmd
"$PROBE" -mode setup -profile inventory-origin -dir "$NEW_TEST_PARAMS"
PYTHONPATH=.:projects/groth16/reference:projects/cctp/reference:projects/cctp/recursion \
  ../cctp-test-tools/venv/bin/python - "$NEW_REPORT" "$PROBE" "$NEW_TEST_PARAMS" "$NEW_PROOF" <<'PY'
import json
from pathlib import Path
import sys
from inventory_origin import prove_origin
report, probe, params, proof = map(Path, sys.argv[1:])
leaves = [bytes.fromhex(item["source_leaf"]) for item in json.loads(report.read_text())["origins"]]
prove_origin(probe, params, proof, leaves)
PY
```
