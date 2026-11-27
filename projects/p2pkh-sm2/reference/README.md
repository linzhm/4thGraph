# P2PKH-SM2 reference guide

[简体中文](README.zh-CN.md) · [Project overview](../README.md)

## Run the tests

Run the commands below from `projects/p2pkh-sm2/reference`. Use Python 3.12
or later and OpenSSL with SM2 and SM3 support for the local tests.

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
```

These tests compare SM3 padding boundaries and fixed-prefix states against the
host SM3 implementation, check the published SM2 vector, and verify a payment
signed with an OpenSSL-generated key. The local Script evaluator exercises the
generated opcodes. The complete-input tests also use independent engines.

On Linux x86-64 with Rust and Cargo, install the [reference dependencies](requirements.txt)
and run the complete-input tests against the pinned chain-gang extension and
BSV Node 1.2.3. The differential tests match the installed Git revision to
requirements.txt and require a known rejection reason for negative cases.

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest -v test_sighash
bash verify.sh
```

The node launcher checks the downloaded archive against a repository-pinned SHA-256 digest
and uses a temporary regtest directory with no peers. It does not broadcast
transactions. Tests cover consecutive transfers, modified inputs and outputs,
invalid keys and scalars, incorrect user IDs, forged preimages, and extra
witness items.

## Implementation map

| Source | Role |
| --- | --- |
| [`sm2.py`](sm2.py) | Curve parameters, ZA, signature verification, and a test signer that takes an explicit nonce |
| [`sm3_script.py`](sm3_script.py) | Emits SM3 as unrolled Script bytecode |
| [`p2pkh-sm2.fth`](../../../src/fourthgraph/stdlib/wallet/p2pkh-sm2.fth) | Lock construction, curve arithmetic, verification and PUSHTX transaction binding |
| [`asm/`](asm/) | Reference assembly for byte-for-byte comparisons and isolated curve tests |
| [`p2pkh_sm2.py`](p2pkh_sm2.py) | Wallet API and external signing callback |
| [`signed_data.py`](signed_data.py) | SignedData payment adapter, structural validation, and signature verification |

Fixture private keys and nonces are public test data. Use an external signer
for production keys.

## v1.0.0 template and Chronicle conformance

The zero-owner script is 144,925 bytes. Its SHA-256 is
`196dfcb8244e863521447c7069297d31938fbd80a83d5976af618cf7fbcf9462`.
The generator and Python constructors emit template version `1` by default.
The [layout manifest](../versions/v1.0.0/layout.json) pins the canonical bytecode,
and the [payment vector](../versions/v1.0.0/spend-all.json) pins a complete BIP143
payment. [16 deterministic preimages](../versions/v1.0.0/sighash-modes.json)
cover all paired modes and each unpaired SINGLE variant.

The script executes all SM3 compression rounds. It reuses powers of two
during rotations and reductions, uses shorter stack operations for nearby
operands, and simplifies the Boolean functions in the last 48 rounds.
The complete-input cases cover BIP143 and Chronicle OTDA, including mixed
inputs, fully SM2 two-input/two-output payments, malformed preimages signed
by the correct SM2 test key, and spends across the Chronicle activation
boundary. The activation cases use transaction version 1 on both sides to
isolate the effect of the activation flags.

[Standard vector](../versions/v1.0.0/sm2-standard.json) · [BSV Node source](https://github.com/bitcoin-sv/bitcoin-sv/tree/6504a3aff65ba97c0f6c80962b033e35ecbfed4b) · [chain-gang source](https://github.com/linzhm/chain-gang/tree/8b60b71a12a69fdcb465d3e627dbf6f43d6ed081)

<a name="point-kernels"></a>

## Reproduce the point kernels

Template `5` compiles the homogeneous point formulas with the optimizing Forth compiler. The compiled kernels preserve the signed residues and infinity handling of templates `3` and `4`. Rebuild the frozen kernels from the repository root.

```sh
PYTHONPATH=src:. python projects/p2pkh-sm2/reference/point_kernels.py /tmp/sm2-point-kernels.json
cmp /tmp/sm2-point-kernels.json projects/p2pkh-sm2/versions/v1.5.0/point-kernels.json
```

[Point formulas](point-formulas.fth) · [Kernel compiler](point_kernels.py)

<a name="otda-constructor"></a>

## Reproduce the OTDA constructor

The wallet loads the frozen program and checks its byte length and SHA-256 against the layout manifest. The offline generator starts with point arithmetic blocks and discovers reusable spans in the template. Templates `1` through `5` also seed named SM3 ranges. For templates `2` through `7` it evaluates which copied fragments are worth caching, tries a dictionary ordered by reuse frequency and selects the smallest serialized encoding. Rebuild the programs from the repository root and compare them with the checked-in files.

```sh
python projects/p2pkh-sm2/reference/generate_otda_constructor.py /tmp/sm2-otda.hex
cmp /tmp/sm2-otda.hex projects/p2pkh-sm2/versions/v1.1.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 2 /tmp/sm2-otda-v2.hex
cmp /tmp/sm2-otda-v2.hex projects/p2pkh-sm2/versions/v1.2.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 3 /tmp/sm2-otda-v3.hex
cmp /tmp/sm2-otda-v3.hex projects/p2pkh-sm2/versions/v1.3.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 4 /tmp/sm2-otda-v4.hex
cmp /tmp/sm2-otda-v4.hex projects/p2pkh-sm2/versions/v1.4.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 5 /tmp/sm2-otda-v5.hex
cmp /tmp/sm2-otda-v5.hex projects/p2pkh-sm2/versions/v1.5.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 6 /tmp/sm2-otda-v6.hex
cmp /tmp/sm2-otda-v6.hex projects/p2pkh-sm2/versions/v1.6.0/otda-constructor.hex
python projects/p2pkh-sm2/reference/generate_otda_constructor.py --version 7 /tmp/sm2-otda-v7.hex
cmp /tmp/sm2-otda-v7.hex projects/p2pkh-sm2/versions/v1.7.0/otda-constructor.hex
```

The constructor tests compare exact preimage, public key, and signature stack values, then verify complete spends against BSV Node and chain-gang. [Layout and fingerprint](../versions/v1.1.0/layout.json) · [Wallet integration](../docs/sdk.en.md)

## SignedData payment interop

[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)
specifies the SM2 signed message container. A configured provider can return
`SignedData` with the signature, algorithm identifiers, signer identifier and
optional content. The existing wallet callback accepts the raw 64-byte `r || s`
authorization. The adapter bridges these formats before the wallet builds the
input witness.

```python
from p2pkh_sm2 import sign_input
from signed_data import signed_data_signer

signer = signed_data_signer(provider, public_key, signer_identifier=pinned_der_issuer_and_serial)
signed_tx = sign_input(tx, input_index, funding_raw, public_key, signer, sighash_type)
```

`provider(message, user_id)` returns DER bytes. Pin the public key and complete
DER `IssuerAndSerialNumber` from trusted configuration. Section 8, tables 2
and 3 of GB/T 35275-2026 specify `SignedData.version = 1`,
`SignerInfo.version = 2`, the issuer-and-serial identifier, and the SM2-1
signature algorithm. Both verification entry points enforce these rules.
The payment adapter accepts both the SM3 OID and the unkeyed SM3 OID used
by Appendix A.1. Both signer CLIs use unkeyed SM3.
For these digest identifiers and the signature identifier, the adapter
accepts omitted parameters or an empty DER NULL. Appendix A.1 uses NULL
for the unkeyed SM3 and SM2-1 identifiers.

The payment adapter verifies one direct SM2 signature over the approved 32-byte payment
message with the pinned public key and the template's fixed SM2 user ID. If the
envelope includes content, its bytes must match the payment message. The
adapter checks the DER structure of embedded certificates, revocation lists
and unsigned attributes. It checks for a nonempty certificate issuer, a
positive certificate serial number encoded in at most 20 octets and a CRL
with a nextUpdate. Embedded metadata also has version and extension
structure checks. The configured public key determines payment
authorization. An application that uses PKI establishes certificate trust
separately.

With `signedAttrs`, the signer signs the DER attributes. Such a signature
requires a verifier for that signed payload. The payment adapter rejects it
because the current template verifies the transaction message directly.

The [Rust signer](interop/rust-signer/README.md) uses RustCrypto `sm2` and
`der`. The [Python signer](interop/python-signer/README.md) uses OpenSSL
for the signature and `asn1crypto` for the envelope. Both provide the same
CLI and JSON fields. `verify.sh` builds the Rust signer with Cargo and
replays attached BIP143 and detached Chronicle OTDA payments from both
signers through BSV Node and chain-gang. The suite also verifies emitted
signatures in OpenSSL, rejects invalid envelopes and checks byte-for-byte
witness equivalence with the raw-signature path.

The [SignedData acceptance fixture](signed-data-acceptance.md) exhausts its
270-row payment matrix and 128-row optional metadata matrix. It records the
historical Appendix A.1 replay and maps the tests to the standard's clauses.

## SignedData signature verification

Use `verify_signed_data` to verify v2 `SignerInfo` entries with trusted keys.
The mapping keys are complete DER issuer-and-serial identifiers. Each value
supplies the authenticated SM2 public key and user ID for that signer.

```python
from signed_data import verify_signed_data

content = verify_signed_data(envelope, {
    signer_a_id: (signer_a_public_key, signer_a_user_id),
    signer_b_id: (signer_b_public_key, signer_b_user_id),
}, detached_content=original_content)
```

Omit `detached_content` for an attached envelope. Verification requires at
least one signer and a valid signature from every listed signer. It handles
direct signatures over the content octets and signatures over the DER
`signedAttrs` field. For a signer with attributes, it also checks that the
sole `messageDigest` value matches SM3 of the content octets. The caller
establishes signer trust and any certificate path or revocation policy.

The general verifier expects the SM2 data content type by default. Supply
`expected_content_type` as a trusted dotted OID for other application types.
The expected type is a caller policy. A direct signature covers content
octets. To authenticate the type with the signature, set
`require_signed_content_type=True`. Each signer must then include one
signed `contentType` attribute matching `eContentType`. The verifier also
checks this match whenever the attribute is present.

The envelope accepts SM3 OIDs `1.2.156.10197.1.401` and
`1.2.156.10197.1.401.1` in digest fields, and SM2-1 OID
`1.2.156.10197.1.301.1` in the signature algorithm field. Each accepts
absent parameters or the exact DER NULL `05 00`. The required digest in
`signedAttrs` uses PKCS #9 OID `1.2.840.113549.1.9.4` and carries one DER
OCTET STRING of 32 bytes. [Profile evidence](signed-data-acceptance.md#signed-attributes-and-algorithm-parameters)

The general verifier and format checker require each signer's digest OID
in `digestAlgorithms` and reject duplicate OIDs in that collection. Absent
parameters and DER NULL identify the same OID. Other DER SET OF collections
retain their field-specific rules. For example, verification deduplicates
identical signer records. The direct payment adapter retains its existing
single-SM3-identifier compatibility.

The general signature verifier uses the original DER `[0]` field bytes
for GB/T 35275-2026 `signedAttrs`. Select `signed_attrs_encoding='cms-set'`
explicitly for a CMS-style signature over the universal SET encoding.
Each verification uses the selected encoding. [Encoding evidence](signed-data-acceptance.md#signed-attributes-and-algorithm-parameters)

### SignedData resource limits

The format check, general verifier and payment adapter share local parsing
limits. An envelope may occupy up to 8 MiB, contain 65,536 DER elements and
reach a nesting depth of 32. Traversal charges each encoded TLV's size to a
shared 64 MiB budget, including values inside embedded X.509 extensions.
Each attribute set and each attribute's value set may contain up to 1,024
entries. The general verifier accepts up to 64 MiB of detached content.
Budget exhaustion raises `SignedDataLimitsExceeded`.

### Structure and ASN.1 schemas

For schema-aware `AttributeValue` validation, pass `attribute_schemas`, a
mapping from dotted attribute OIDs to `asn1crypto` ASN.1 classes. Each
declared value is decoded as its ASN.1 type and checked against the canonical
DER re-encoding. `messageDigest` has a built-in OCTET STRING check.
`MissingAttributeSchema` identifies an encountered OID whose schema is
unavailable. The configured schema defines the type and any application
constraints. [Acceptance evidence and remaining scope](signed-data-acceptance.md#additional-chapter-8-evidence)

Use `validate_signed_data_format(envelope, require_signer=True,
attribute_schemas=...)` for Chapter 8 framing, signer count and the
implemented X.509 extension profile checks. Omit `require_signer` to
inspect metadata fixtures with an empty `SignerInfos` set. The format
check can parse a detached envelope without its content.
It returns normally when the format checks pass. Use `verify_signed_data`
with authenticated signer keys and any detached content to verify a
signature and obtain the signed bytes.

Pass `extension_schemas` to the format validator as a mapping from dotted
extension OIDs to `asn1crypto` ASN.1 classes. A supplied schema checks each
value against its canonical DER encoding. In this mode, an otherwise
unrecognized extension without a supplied schema raises
`MissingExtensionSchema`. The check applies to certificates, CRLs and
individual revoked-certificate entries.

## Certificates and revocation lists

Use `validate_crl_series(crls, extension_schemas=...)` to compare the
issuance numbers of DER CRLs for one authenticated issuer and scope. Use
`validate_crl_pair(complete_crl, delta_crl, extension_schemas=...)` to check
whether a numbered complete CRL meets the metadata requirements for
combining with a delta CRL. The caller authenticates both lists against
the same authorized signing key before relying on the pair check. Pass
objects from the envelope or from another authenticated source.

Use `merge_crl_revocations(complete_crl, delta_crl, published_crl=...)`
to build a snapshot for the delta CRL's number, validity times and
scope. Pass `issuer_certificate` as trusted DER to verify every supplied
CRL with that certificate's key, or authenticate the CRLs before calling.
Supply `sm2_user_id` as the configured signer ID when the CRL uses SM2.
`verify_crl_signature(crl, issuer_certificate, sm2_user_id=...)` provides
the same verification for one CRL. Establish the certificate path and
the issuer's authority for the CRL scope before using these checks.

Supply `published_crl` to compare with a complete CRL released at the
same `thisUpdate` and number. The snapshot's
`revocation_for(issuer_name, serial_number)` takes a `cryptography.x509.Name`
and returns the scoped revocation entry or `None` if absent. For an
indirect entry with multiple distinct directory names, an
`issuer_resolver(serial_number, candidates)` can select the authenticated
issuer name from the supplied candidates. Distribution-point applicability
and reason coverage can be evaluated with
`assess_certificate_revocation(certificate, snapshots, validation_time=...)`.
Build the snapshots with `load_crl_snapshot(crl, issuer_certificate, ...)`
for a numbered complete CRL or pass `issuer_certificate` when merging. For
the supplied timezone-aware time, the assessment returns `revoked`,
`unrevoked` when the available lists cover every reason, or `undetermined`
when coverage is insufficient. The caller supplies the available CRLs and
can pass `trust_anchor` and `intermediates` to the assessment to validate
the target and CRL signer paths under one explicitly trusted DER
certificate. This mode uses OpenSSL with the supplied validation time and
an isolated process environment. It selects the binary from conventional
system install directories. Pass an absolute `openssl_path` to pin a
trusted installation. The verifier uses the selected build's default
providers, with ambient OpenSSL configuration and module overrides excluded.
`sm2_user_id` configures the separate CRL signature
check. Direct CRLs must use the public key of the target's selected issuer.
Freshness and conflict checking use the issuer name, public key and CRL
scope. An indirect CRL must match a distribution point signed by the
target's issuer and have an authorized signer on, or issued by a CA on,
the target path. Ambiguous same-name delegated keys for the same applicable
distribution point contribute no coverage.

Callers with independently validated paths can omit `trust_anchor` and pin
the authenticated target `issuer_certificate`. When neither is supplied,
the direct CRL signer's key must verify the target certificate signature
using the installed cryptographic library. The caller authenticates
delegated CRL signing keys when using externally validated paths.

Set `require_chain_revocation=True` with the explicit trust anchor to
require fresh, complete revocation evidence for each selected intermediate
and CRL signing certificate. Supply a CRL snapshot from each certificate's
validated parent. The check rejects an ambiguous intermediate path,
missing coverage, and revoked intermediates or signers.
