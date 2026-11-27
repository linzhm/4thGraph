# Lamport OTS developer guide

[简体中文](developer.zh-CN.md) · [Project overview](../README.md)

<a name="protocol"></a>

## Protocol

The 16,384-byte public key contains 256 ordered pairs of SHA-256 commitments. The signer discloses one 32-byte secret per digest bit. The full-key payment lock verifies the selected commitments directly. The committed profiles verify SHA-256 of the reconstructed public key. All payment profiles bind the digest to the spending input under the requested sighash. [Wire encoding and native binding](spec.md)

<a name="optimization"></a>

## Forth optimization

`forth_committed_locking_script(public_key)` compiles a typed Forth reconstruction fragment. The lock uses a byte mask to select the ordering of each public-key pair. It accepts the same proof layout and transaction modes as the original committed lock. Use SDK profile `committed-key-forth` to reproduce the candidate independently of the default full-key profile. [Stack invariant and byte breakdown](optimization.md) · [Forth source](../reference/committed-verifier.fth)

`compact_forth_committed_locking_script(public_key)` uses the same reconstruction fragment and compacts the fixed-r binding to reach 6,830 bytes. Select `committed-key-forth-compact` to create that experimental output. [Binding byte breakdown](optimization.md#compact-transaction-binding)

<a name="security"></a>

## Signing and recovery

Reserve and consume one fresh key per output before releasing a signature. Confirm the funding outpoint before authorizing a child and preserve consumption state through backups and concurrent requests. Rebroadcast the saved signed bytes after a transient failure. A different funding outpoint requires a different digest. The reference requires `allow_unpaired_single=True` to authorize an input that commits to zero outputs through unpaired SINGLE. [Threat model and recovery procedure](security.md)

<a name="validation"></a>

## Validation and benchmarks

The 408-row domain tests authorization for every supported mode and profile. The committed profiles also test every proof block and the Chronicle activation boundary. The reproduction commands use an independent BSV Node alongside the pinned chain-gang package. Historical v0.1.0 vectors are kept with the release. [Acceptance domain](acceptance.md) · [Executed checks](validation.md) · [Measurements and lifecycle costs](optimization.md#transaction-and-lifecycle-costs)

<a name="sdk"></a>

## Wallet and reference APIs

Use `WalletClient` for lock creation, recognition and signing. The external callback receives a 32-byte digest and returns an 8,192-byte raw signature. For Python reference use, `sign_spend` authenticates a prepared input against its funding transaction before calling the signer. [SDK quickstart](sdk.en.md#quickstart) · [Reference usage](../reference/README.md)
