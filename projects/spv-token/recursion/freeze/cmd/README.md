# CCTP rule proof CLI

Run from `projects/spv-token/recursion`. Use a new test parameter directory for the selected profile and pass the exact versioned, transaction-derived statement as hex. The example uses the checked-in Script control vector.

```sh
freeze_run=$(mktemp -d)
go build -o "$freeze_run/freeze" ./freeze/cmd
"$freeze_run/freeze" -mode setup -profile plain -dir "$freeze_run/setup"
statement_hex=$(python3 -c 'import json; print(next(v["statement"] for v in json.load(open("freeze/testdata/script-control.json")) if v["case"] == "freeze"))')
"$freeze_run/freeze" -mode prove -dir "$freeze_run/setup" -statement "$statement_hex" -out "$freeze_run/proof.json"
```

The default `plain` profile exports the public key and proof in the shape read by `snarkjs_adapter.load_artifacts(artifact, artifact, artifact["public_signals"])`. Use `-profile bsb22` at setup to export a proof read by `committed_verifier.load_artifact(artifact)`. Both use the same statement and two big-endian public limbs. Setup creates randomized test-only parameters and records the constraint-system fingerprint and native key hashes in `manifest.json`. Prove verifies the generated proof with the saved verifying key before writing the artifact.

For a two-input, two-output conservation proof, create a separate setup with
`-profile conservation`. Pass the 585-byte transaction-derived statement as
hex to the same `prove` command using that setup directory. The proof uses
plain BLS12-381 Groth16 and the same snarkjs artifact fields. The manifest
identifies the conservation circuit and its independently generated keys.
The spending scripts authenticate the transaction context, token states, and
holder signatures.

Use `-profile parent-checkpoint` for the bounded parent transaction fixture.
Setup uses a separate directory. Prove takes `-parent` with the full 332-byte
parent transaction in hex and `-statement` with the 174-byte versioned
checkpoint statement in hex. The circuit derives the SHA-256 checkpoint after
256 bytes, finishes the parent txid from that state, and commits the suffix
and two serialized output fields. The plain BLS12-381 proof uses the same
snarkjs artifact format. The spending Script must bind the proven parent to
the actual input outpoint and selected output.

Use `-profile parent-checkpoint-token` with fresh test parameters for the
3,433-byte legacy-v2 Token unfreeze parent. Both checkpoint profiles use a
174-byte statement. The Token profile fixes two inputs, one active Token
output, and a 1,856-byte checkpoint. Its last 32 statement bytes are zero.
The suffix hash covers the complete serialized output, which the receiver
checks against the actual outpoint and token policy.
