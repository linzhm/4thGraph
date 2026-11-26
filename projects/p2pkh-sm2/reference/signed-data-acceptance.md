# SM2 SignedData acceptance evidence

[简体中文](signed-data-acceptance.zh-CN.md) · [Reference guide](README.md)

This record describes what the payment adapter, general signature verifier,
and certificate revocation assessment check. The payment adapter verifies
a single direct signature over the approved transaction message. The general
verifier accepts one or more trusted signers and supports direct signatures
and signed attributes. Both signature entry points require outer
`SignedData.version = 1` and inner `SignerInfo.version = 2`.
[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

## Acceptance decisions

| Scope | Disposition |
| --- | --- |
| SM2 payment | Accepted for the declared single-signer, direct-signature wallet profile. The payment matrix, isolated version-octet tests, independent provider, and BSV Node replay are the release evidence. |
| General SignedData | Accepted for the documented project profile. The strict format check and verifier enforce the minimum signer count. The verifier uses the original DER `[0]` view for signed attributes by default and supports a separately selected CMS preimage. The algorithm parameter matrix and attribute OID choices are recorded below. |
| PKI assessment | Accepted for the selected trust anchor, applicable caller-supplied CRLs, and the upstream evidence conditions described below. |
| Chapter 8 encoding decisions | The project accepts the per-OID parameter table and PKCS #9 `messageDigest` identifier below. The acceptance scope is this project profile. Open attribute and extension values depend on the schema for their OID. |

## Regression witnesses from the review of `3b54f9f`

| Rule | Executable evidence |
| --- | --- |
| GB/T 35275-2026 §6.6, GB/T 20518-2018 §§5.2.3.4, 5.2.3.6 and 5.3.3.3, and RFC 5280 Appendix A.1 | The three SignedData entry points exercise RFC 5280 naming attribute types and character bounds, including a two-character `countryName` in PrintableString and multibyte DirectoryString bounds. Independently signed metadata exercises the same country field in certificate issuer, certificate subject, and CRL issuer names. Unknown naming OIDs retain open DER values. |
| X.690 §§8.23.7–8.23.8 | Direct and nested BMPString and UniversalString values exercise fixed-width encodings, valid supplementary characters in UniversalString, truncated values, and forbidden surrogate encodings. The signed-attribute fixtures use signatures that OpenSSL independently verifies. |
| RFC 5280 §§4.1.2.5, 5.1.2.4–5.1.2.6 | Independently signed certificates and CRLs exercise ascending, equal, and descending endpoints across the 1999/2000 and 2049/2050 boundaries. `revocationDate` fixtures test the 2049/2050 time type boundary and a forbidden fractional second. The CRL fixtures also run through the standalone CRL series entry point. |

[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC) ·
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[X.690](https://www.itu.int/rec/T-REC-X.690/en) ·
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

## Regression witnesses from the review of `49175f6`

| Rule | Executable evidence |
| --- | --- |
| GB/T 35275-2026 §6.6 and GB/T 20518-2018 §§5.2.3.2 and 5.2.3.4 | Format checking, general verification, and the payment adapter accept a canonical 20-octet serial, including a required sign octet, and reject a 21-octet serial. The same entry points check the type and character count of `commonName`, including a 64-character multibyte control. |
| X.690 §§11.7–11.8 | Signed and unsigned attributes exercise impossible calendar dates and clock values alongside leap-day, leap-second, and fractional-second controls. The signed controls are signed and verified by OpenSSL. |
| RFC 5280 §5.2.5 | A user-only CRL contributes zero reason coverage for a valid v1 certificate. An unrestricted CRL can determine the same certificate's status. The user-only CRL can determine a v3 subject's status. |
| RFC 5280 §4.1.2.5 | Boundary cases cover the target, intermediate, CRL signer, and trust anchor. The issuer expiring at the same instant the target becomes valid is usable. The expired alternative is filtered before path building. |

[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC) ·
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[X.690](https://www.itu.int/rec/T-REC-X.690/en) ·
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

## Run the acceptance fixture

Install the pinned [reference dependencies](requirements.txt). Run the finite
fixture with Python 3.12 and OpenSSL with SM2 and SM3 support. The fixture
generates dedicated test keys and checks signatures independently in OpenSSL.

From the repository root:

```sh
PYTHONPATH=src:.:projects/p2pkh-sm2/reference python -m unittest -v test_signed_data_acceptance
```

For BSV Node 1.2.3 replay, run `bash projects/p2pkh-sm2/reference/verify.sh`.
It builds the [independent Rust signer](interop/rust-signer/README.md) with
Cargo and also invokes the [Python signer](interop/python-signer/README.md).
Set `SM2_SIGNED_DATA_SIGNER` to the absolute executable path of a prebuilt
Rust signer to skip the Cargo build. The tests exercise both CLIs, verify
the signatures in OpenSSL and replay attached ForkID and detached Chronicle
OTDA spends through BSV Node and chain-gang.

## Complete enumeration of the declared domain

| Axis | Values exercised |
| --- | --- |
| Encoded `SignerInfo.version` | 1, 2, 3 |
| Encoded `SignedData.version` | 1, 2 |
| Encapsulated content | Detached, approved message, different message |
| Signature algorithm identifier | SM2-1, SM2-with-SM3, SM3 |
| Authorization | Direct, signed attributes, different key, different SM2 user ID, different signed message |

The domain has \(3 \times 2 \times 3 \times 3 \times 5 = 270\)
tuples. On each run the fixture checks that the axes have distinct values,
every visited tuple belongs to the domain, each tuple is visited at most
once, and exactly 270 tuples were visited. A subset of a finite set with the
same cardinality equals the whole set. These assertions therefore detect a
missing, repeated, or unexpected row.

The fixture specifies the two accepted tuples explicitly. They are the
attached and detached forms of the valid version pair and a direct SM2-1
signature. An accepted row must return the exact raw signature decoded
independently from OpenSSL's output. The other 268 rows
must raise `ValueError`. This checks both false acceptance and false rejection
within the declared domain.

## Complete enumeration of optional metadata combinations

The second matrix holds the payment signature valid and crosses both
content modes with four states for each of
`certificates`, `crls` and `unsignedAttrs`. The states are absent, empty set,
one valid member and one member encoded as ASN.1 `NULL`. The same membership,
uniqueness and cardinality checks establish coverage of all
\(2 \times 4^3 = 128\) tuples.

The acceptance set follows from the field grammar. Certificates and CRLs
permit absent, empty and valid, while the optional unsigned attribute set
must have at least one attribute when present. Thus
\(2 \times 3 \times 3 \times 2 = 36\) tuples must yield the exact
payment signature. The other 92 must report the first invalid field.
OpenSSL independently generates and parses the test certificate and CRL.
Separate mutations cover a CRL placed in the certificate field, a certificate
placed in the CRL field, empty sequences presented as either type, and
invalid OID, tag, length and order in unsigned attributes.
Bypassing the validator for each optional field in turn made this matrix
fail in all three runs. Each original wrong-type counterexample therefore
checks the adapter's actual decision.

## Clause-to-test traceability

| Rule | Executable evidence |
| --- | --- |
| §5 outer `ContentInfo` | Correct content OID in every matrix row. Wrong OID, every proper prefix of a valid attached envelope, all 256 one-byte suffixes and targeted DER length violations are rejected. |
| §8 table 2 `version` and table 3 `version` | Both entry points accept the same valid payment envelope. Two independently tested variants alter exactly one octet, setting inner version to 1 or outer version to 2. Both entry points reject each variant with the corresponding version error. The matrix crosses the encoded versions with content and signature cases. |
| §8 table 2 `digestAlgorithms` and table 3 `digestAlgorithm` | The fixture crosses SM3 and unkeyed SM3 with absent or DER NULL parameters in both fields. Wrong OIDs, keyed SM3, malformed NULL and a missing identifier are tested individually. The payment profile also rejects two entries that each pass as the sole SM3 entry. This isolates the payment cardinality rule. |
| §8 table 2 `encapContentInfo` | Matrix covers attachment, detachment and a different message. A different content type is rejected by the payment profile. |
| §6.6 and §8 table 3 `issuerAndSerialNumber` | Pinned identifier in positive cases. Wrong identifier, SKI and malformed configured serial numbers are rejected. A matching pinned and encoded identifier with ASN.1 `NULL` in the issuer RDN position also fails, along with empty RDN and malformed attribute cases. |
| §8 table 2 `signerInfos` | Payment fixtures reject zero signers, accept one and reject two. The general verifier accepts two trusted OpenSSL signers in attached and detached modes, including a mixed direct and signed-attribute envelope. A wrong SM2 user ID on the second signature or an absent trusted key fails the envelope. Repeated signature entries with the same authenticated payload share one message digest and one SM2 verification. |
| §8 table 3 `signedAttrs` and signing rules after table 3 | OpenSSL verifies independently signed attribute sets with both matching and mismatching `messageDigest`. The general verifier requires exactly one digest attribute with one OCTET STRING matching the SM3 of the original content. Signed fixtures cover missing, duplicated, mistyped, truncated and mismatching digests, a wrong DER signing tag and unsorted attributes. The payment policy rejects attribute signatures. |
| §8 table 3 `signatureAlgorithm` and `signature` | Crossed algorithm and signature modes. Separate cases exercise missing, non-canonical and out-of-range signature integers in both scalar positions. |
| §8 table 2 `certificates` and `crls`, table 3 `unsignedAttrs` | Both content modes cross all declared member states. Separate regressions reject empty issuers, zero and overlong certificate serial numbers, CRLs without `nextUpdate`, and malformed BOOLEAN and INTEGER values. Controls include the maximum valid 20-octet certificate serial and canonical signed integers. |
| GB/T 20518-2018 §§5.2.3.3 and 5.3.3.2, certificate and CRL signature algorithms | Both entry points accept intact OpenSSL metadata. With the original signed body and signature value preserved, they reject replacing the outer algorithm OID or changing only its parameters. |
| X.690 §§8.6.2, 8.19, 10.2 and 11.2.1, open attribute values | Seventeen encodings exercise BIT STRING padding and primitive tags, OID termination and minimal encoding, and primitive OCTET STRING. Each appears as a direct or nested value and runs through payment `unsignedAttrs` and general `unsignedAttrs` and `signedAttrs`. OpenSSL independently verifies every signed-attribute signature. |

The unittest module adds an executable traceability check after the fixture
tests. The registry lists each field of §8 tables 2 and 3 and the required
witnesses for that field and the signature input rules. Each witness records execution
after asserting its expected outcomes. The final check requires exact
equality between the required and observed witness sets, and between the
declared table fields and the registry's table entries.

The single-octet version test fails in both entry points when either shared
version check is weakened to accept the mutated envelope.

Each of seven in-memory mutations caused its targeted fixture to fail.
The mutations bypassed certificate issuer and serial-width checks, CRL
`nextUpdate`, open-value INTEGER encoding, content-digest comparison,
second-signer verification and rejection of extra algorithm parameters.

With `cryptography` 43.0.0, the new certificate, CRL and attribute fixtures
caught 68 incorrect acceptances on the pre-fix implementation. All these
cases pass with the fix. Six independent mutations removed the matching
algorithm check or one of the BIT STRING, OBJECT IDENTIFIER and OCTET STRING
checks, and each mutation failed its targeted assertions.

For signed attributes, the verifier uses the PKCS #9 `messageDigest` OID
1.2.840.113549.1.9.4 and the field's DER `[0]` tag by default. The OpenSSL
fixtures independently sign both this input and the separately selected CMS
SET input. Appendix A.1 supplies a direct-signature example. [RFC 5652 §§5.4 and 11.2](https://www.rfc-editor.org/rfc/rfc5652)

The completeness claim covers the two declared products and the explicit
prefix and suffix families. The other tests are targeted witnesses. More
schema-specific DER evidence would be needed for arbitrary open attribute
types and complete X.509 certificate and CRL profiles. Certificate path and
revocation policy are established externally. The verifier requires at
least one authenticated signature for acceptance. The ASN.1 `SignerInfos`
grammar also describes empty sets.

GB/T 35275-2026 §6 uses AlgorithmIdentifier. GB/T 20518-2018 §5.2.2
declares its parameters optional and leaves parameter syntax to the
algorithm. The GB/T 33560 identifier tables supply the SM3, unkeyed SM3
and SM2-1 OIDs. Appendix A.1 demonstrates explicit DER NULL for the
unkeyed SM3 and SM2-1 fields in the envelope. The envelope verification
profile accepts absent parameters or empty DER NULL and tests rejection
of nonempty NULL, other parameter tags and repeated parameters. Embedded SM2
certificates and CRLs require absent parameters in their own signature
algorithm identifiers under GB/T 20518-2018. [GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[GB/T 33560-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=9BF813CEEAFB58A19534FF861465D8FD)

## Regression checks from the review of `4bcc9d5`

`SignedDataReview` runs 108 conforming controls and 120 rejection cases
for the encoding matrix below.
Each rejection test requires every case to raise `ValueError` and reports
any case that returns the valid payment signature or content. Fixture setup
checks the OpenSSL signatures and runs every case before these assertions.
The control test checks the number of cases and requires every conforming
sample to pass.

| Rule | Rejection cases |
| --- | --- |
| GB/T 20518-2018 §§5.2.2 and 5.3.2 | Four checks for explicit NULL in both SM2 signature algorithm identifiers of a certificate or CRL. Both verification entry points also accept controls with omitted parameters. |
| GB/T 20518-2018 §§5.2.2 and 5.3.2 and GB/T 35276 §7.3 | Twelve checks reject an incorrect signature tag, a zero scalar or a non-octet-aligned BIT STRING in the embedded signature value of an SM2 certificate or CRL. |
| GB/T 20518-2018 §§5.2.3.5.2 and 5.3.3.4–5.3.3.5 | Eight checks replace one 2049 time at a time with GeneralizedTime, covering certificate `notBefore` and `notAfter` and CRL `thisUpdate` and `nextUpdate`. Controls encode both fields as UTCTime in 2049 and GeneralizedTime in 2050. |
| X.690 §§8.4, 8.9–8.12, 8.20, 8.23, 10.2 and 11.7–11.8 | Ninety-six checks cover primitive SEQUENCE and SET, constructed strings, UTF-8 and character repertoires, RELATIVE-OID, ENUMERATED and DER time forms. Each case runs as a direct and nested value through payment `unsignedAttrs` and general `unsignedAttrs` and `signedAttrs`. |

The earlier 72-case rejection fixture reproduced incorrect acceptance of
all its negative cases on `3197dd9`, while its 60 controls passed. A separate OpenSSL replay
constructed 57 checks without the fixture helpers, including a mixed
2049/2050 validity interval, detached content, an RSA certificate with NULL
parameters, and independently signed attribute sets. The repaired
implementation matched every expected outcome.

## Additional Chapter 8 evidence

| Normative area | Evidence | Remaining scope |
| --- | --- | --- |
| GB/T 20518-2018 §§5.2.2, 5.2.4.1 and 5.3.2 | Both verification entry points exercise certificate v1, v2 and v3, CRL v1 and v2, and version restrictions for unique identifiers and extensions. Certificate, CRL and revoked-entry extensions are checked for unique OIDs, DER DEFAULT omission, exactly one wrapped DER value and the supported extension payload type. | Extension-specific rules are tracked below. |
| GB/T 35275-2026 §6.9 and §8 | Schema-aware verification checks a declared open type in both attribute fields. An independent signature remains valid when an inner SET OF is unsorted or the value has the wrong type. The ASN.1 schema check rejects both cases and identifies missing schemas explicitly. The format verifier applies the same declared DER type check to extension values. | Private attribute and extension OIDs require their declaring ASN.1 schemas and profile constraints. |
| GB/T 35275-2026 §8 signer-set cardinality | `require_signer=True` and signature verification require at least one signer in all content modes. The default structural diagnostic can inspect the empty ASN.1 set. A wrong tag fails the format check. One and multiple signers are covered. | Covered for the declared framing and cardinality cases. |
| GB/T 35275-2026 §§6.3–6.4 and §8 signed input | The envelope fixture enumerates 32 combinations of the two digest OIDs and absent or NULL parameters at all three algorithm fields in each content mode. Format validation and both signature entry points execute every row. Independent OpenSSL fixtures pin `[0]` as the project default and require an explicit CMS setting for universal SET signatures, in both content modes. | The signed-attribute rule follows the field named by §8. The matrix verifies the exact parameter encodings in the project table below. |

The v2 certificate structural test uses `asn1crypto` because
`cryptography` rejects certificate version v2 at load time. The
validation runs on the original certificate bytes. Certificate path
validation, trust anchors, and revocation decisions belong to the caller.
An independent OpenSSL replay exercised 74 checks with its own DER
construction, including a v2 certificate with a unique identifier, valid
and duplicate private extensions, CRL version dependencies, and open
values with DER time and RELATIVE-OID encodings.

### Format and X.509 profile witnesses

`validate_signed_data_format` shares parsing with the signature verifier
and applies the following self-contained embedded-certificate and CRL
profile rules. Certificate signatures, certificate paths and revocation
decisions require trusted inputs at the application layer.

| Rule | Executable evidence |
| --- | --- |
| GB/T 20518-2018 §§5.2.3.6, 5.2.4.2.9 and 5.2.4.2.12 | An empty subject requires a critical, nonempty SAN. A CA requires a nonempty subject and critical basicConstraints. Encoding the default `cA FALSE` explicitly fails DER validation. |
| GB/T 20518-2018 §§5.2.4.2.2–5.2.4.2.4 and 5.2.4.2.13 | AKI and SKI are noncritical when present. A CA requires SKI and keyCertSign. keyCertSign and nameConstraints require a CA certificate. |
| GB/T 20518-2018 §5.2.4.2.8 | A policy mapping can map two ordinary OIDs. Both positions reject anyPolicy. |
| GB/T 20518-2018 §§5.3.4.1–5.3.4.5 | CRL AKI and cRLNumber are noncritical, issuerAltName is nonempty, and deltaCRLIndicator and issuingDistributionPoint are critical. Both number fields accept nonnegative DER integers of at most 20 content octets. |
| GB/T 20518-2018 §§5.3.4.6–5.3.4.7 | freshestCRL belongs on complete CRLs, is noncritical, contains at least one distribution point and omits reasons and cRLIssuer. Reason and invalidity date are noncritical, removeFromCRL requires a delta CRL, and certificateIssuer has at least one name. Revoked-entry serial numbers must be positive and fit within 20 DER content octets. |
| GB/T 20518-2018 §5.2.4.1 | A declared private ASN.1 type is checked for certificates, CRLs and revoked entries. Tests exercise valid types, invalid type and SET OF order, and a distinct missing-schema error. |

Remaining X.509 scope includes other extension-specific rules and
application-specific issuer and subject relationships. The
certificate fixture uses independently signed metadata to isolate each
rejection from the signature bytes.
The independent OpenSSL replay now runs 103 checks using a separate DER
constructor. Added cases include a private extension schema, removeFromCRL,
and crossed `signedAttrs` preimages.

The following witnesses add 80 OpenSSL-signed certificate or CRL cases.
Each object is signed and verified independently before it is embedded in a
zero-signer envelope for `validate_signed_data_format`. The zero-signer
envelope isolates metadata validation from content signature verification.

| Normative area | Cases | Executable evidence |
| --- | ---: | --- |
| GB/T 20518-2018 §§5.2.4.2.8, 5.2.4.2.13–14 | 27 | CA-only placement for policy mappings and name and policy constraints. Both subtree fields check nonempty sequences and omission of minimum and maximum. Both policy counters check zero, the DER sign-octet boundary, negative and nonminimal encodings. |
| GB/T 20518-2018 §§5.2.4.2.9–10, 5.2.4.2.15, 5.2.4.2.17 and 5.2.4.3.2–3 | 19 | Empty SAN entries are rejected even alongside a valid DNS name. Issuer alternative names, certificate distribution points, certificate freshestCRL and both information-access extensions have a nonempty list. Information-access extensions are noncritical. The other tested extensions permit both criticality settings. |
| GB/T 20518-2018 §§5.2.4.2.19–22 | 16 | The four defined OIDs each accept a noncritical PrintableString without a caller-supplied schema. Criticality, a different string type and an out-of-repertoire character each cause a distinct rejection. |
| GB/T 20518-2018 §§5.3.3.3, 5.3.3.6 and 5.3.4.5 with ITU-T X.690 §11.5 | 18 | CRL issuer RDN structure, omission of an empty revokedCertificates list, DER revocation time, and each implicit DEFAULT FALSE flag in issuingDistributionPoint. The flag fixtures independently exercise canonical TRUE, explicit FALSE and a noncanonical TRUE octet. |

[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/en)

### Complete and delta CRL relationships

An individual delta CRL requires a `cRLNumber` greater than its
`BaseCRLNumber`. A caller can validate issuance metadata across an
authenticated series or check whether a complete CRL can serve as the
input for a given delta CRL. An envelope can carry a delta CRL while the
complete CRL is available from another source. The caller selects the
series and establishes issuer identity before comparing its metadata.

| Normative area | Executable evidence |
| --- | --- |
| GB/T 20518-2018 §§5.3.4.3–4 and RFC 5280 §5.2.3 | The profile rejects a missing delta number and numbers below or equal to the base. The series fixture independently crosses both CRL roles, the three issue-time orderings and the three number orderings in 36 rows, each run in both input orders. A three-object case checks a repeated number in an unsorted series. |
| RFC 5280 §5.2.4 | The pair fixture crosses the five positions of the complete number around BaseCRLNumber and the delta number with three issue-time positions in 15 rows. It also checks role reversals, differing issuers, and both absent, both equal, one absent and unequal issuing distribution points. |
| RFC 5280 §§7.1, 7.3 | The pair fixture exercises UTF8String and PrintableString comparison, insignificant space and case folding, domain-component case, and differing RDN attribute multiplicity. The distribution point scope is compared by its canonical DER value. |

The fixtures use OpenSSL to sign and verify both CRLs before invoking the
metadata verifier. The issuer-certificate path and publication of the
referenced complete CRL require separate evidence.
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[RFC 5280 §5.2.4](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.4) ·
[RFC 5280 §7.1](https://www.rfc-editor.org/rfc/rfc5280#section-7.1)

### Revocation snapshot and same-time publication

`merge_crl_revocations` checks the pair and compares authority key
identifiers. It indexes each CRL by certificate issuer and serial, applies
delta entries over the complete list, and removes entries marked
`removeFromCRL`. The snapshot uses the delta CRL's number, times and scope.
For an indirect CRL, the first entry defaults to the CRL issuer and later
entries inherit the previous issuer unless a critical `certificateIssuer`
selects a new one. An application supplies an authenticated selection when
that extension contains multiple distinct directory names. Duplicate
issuer/serial entries and unsupported critical extensions fail the merge.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §§5.2.4 and 6.3.3(i)–(k) | A 20-row matrix crosses four complete-list states with five delta actions. It checks additions, replacements, retention, releases including an absent target, explicit or default unspecified reason, UTC dates and metadata inherited from the delta. |
| RFC 5280 §§5.3.3 and 6.3.3(c) | Direct and indirect entry witnesses check per-list issuer inheritance, issuer changes, equal serials at different issuers, criticality and missing or ambiguous DNs. Authority key identifiers agree or both are absent. A different or one-sided identifier fails the merge. |
| GB/T 20518-2018 §5.3.4.3 and RFC 5280 §5.2.3 | The optional same-time complete CRL must match the merged issuer/serial state, including reason and dates. Tests exercise an order-independent match and isolate a missing entry, extra entry, differing reason or dates, wrong number, time, issuer, scope and delta in the complete slot. |
| Independent OpenSSL check | Six test certificates produce 18 CLI verdicts using the complete CRL alone, the pair with `-extended_crl -use_deltas`, and the simultaneous complete CRL. The pair and simultaneous complete verdicts match the snapshot, and the base-only controls distinguish absent and released entries. |

The snapshot represents one scope at the delta's issue time. The
assessment described below combines snapshots for a target certificate.
[RFC 5280 §5.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.3) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### CRL signer authentication

`verify_crl_signature` and the `issuer_certificate` option of
`merge_crl_revocations` bind each CRL to a caller-authenticated issuer
certificate. The merger verifies the complete, delta, and optional
same-time complete inputs with the same certificate key before applying
any revocation entry. For SM2, the verifier uses the certificate's
uncompressed curveSM2 key, the original `tbsCertList` octets, the DER
signature value, and the caller's configured signer ID. The RSA fixture
checks the platform signature verification path independently with OpenSSL.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.3.3(f)–(h) | The signed tests vary the key with the subject and serial fixed, change the issuer DN with the key fixed, and check keyUsage with cRLSign set, clear or absent. Independent counterexamples target each of the complete, delta and optional publication positions. |
| GB/T 20518-2018 §§5.3.2 and 5.3.4.1 | The fixtures vary the key identifier, the authority certificate issuer and the serial independently. The verifier compares a key identifier to a certificate SKI when both are present and tests each of the two authority identifier forms. The CRL signature is checked even when identifiers are absent. |
| GB/T 35276-2017 §§8.1–8.2 | OpenSSL signs and verifies with both a standard-length and an application-specific SM2 ID. The implementation rejects a wrong or unavailable ID, a different curve and an edited `tbsCertList`. |

The relying party supplies the authorized scope. The signer ID is an
explicit configuration input. Certificate paths can be checked during
assessment under a caller-selected trust anchor.
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### Certificate revocation scope and time

`assess_certificate_revocation` combines caller-selected authenticated
snapshots from complete CRLs or merged CRLs. The result is `revoked`,
`unrevoked` or `undetermined`, together with reason coverage. A valid
revocation entry on an applicable snapshot determines `revoked`, whatever
its reason code. Reason masks govern coverage only. An absent entry yields
`unrevoked` only when the usable snapshots cover all eight reasons.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.3.3(a) | Fixtures cover an inclusive `thisUpdate`, an exclusive `nextUpdate`, future and expired lists, release after an older hold, conflicting revisions and an entry dated after the assessment time. The latest available issue for a scope controls freshness. |
| RFC 5280 §6.3.3(b) and explicit distribution-point policy | Positive and negative witnesses vary direct and delegated issuer names, the indirect flag, IDP matching, full and relative names, and CA, end-entity and attribute-certificate scopes. The assessor uses the issuer default point only when the certificate omits the distribution-points extension. |
| RFC 5280 §§6.3.2 and 6.3.3(d)–(l) | Fixtures vary certificate and CRL reason masks independently, combine complementary scopes or distribution points, and distinguish partial coverage from a conclusive result. A future-dated entry or reason contradicting its CRL's mask prevents that snapshot from contributing coverage for the entry. |
| OpenSSL comparison | CLI fixtures check five cases for matching and mismatched scope, revocation, a future CRL and an expired CRL. The six existing base/delta certificate outcomes also exercise the assessment against independently verified CLI results. |

The caller supplies the applicable CRLs, any authenticated indirect issuer
selection and a validation time. The complete-only snapshot loader uses
numbered CRLs. Distribution name matching normalizes directory names and
compares other forms using their decoded values.
[RFC 5280 §6.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.2) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### Pinned certificate paths for revocation assessment

Pass `trust_anchor` and any untrusted DER `intermediates` to
`assess_certificate_revocation`. The verifier checks `notBefore` and
`notAfter` inclusively for the endpoints, trust anchor, and every available
intermediate, then passes only time-valid certificates to OpenSSL. OpenSSL
validates both paths with a trust store containing only the explicit anchor.
The target uses generic path validation and the CRL signer uses
the CRL-signing purpose. Path policy processing starts with `anyPolicy`.
A single 15-second budget covers path validation. Strict revocation
assessment maps OpenSSL's selected chain to supplied DER subjects in process.
Unused intermediates require no additional OpenSSL processes.
A caller can also pin an intermediate as its
trust anchor. Path rejection aborts the assessment.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.1 | The fixtures exercise a missing intermediate, a modified certificate signature, certificate validity, name constraints, maximum path length, CA key usage, an unrecognized critical extension and explicit policy constraints. Positive controls exercise permitted names and matching explicit policies. |
| RFC 5280 §6.3.3(f) | A delegated RSA CRL signer and its target validate under one anchor. A root with the same subject and a different key, a signer rooted elsewhere, and an unrelated root presented as an intermediate are rejected. A separate OpenSSL-issued SM2 chain exercises the target and the CRL signer under one anchor and rejects a missing SM2 intermediate. |

Path verification uses the local OpenSSL certificate signature behavior.
The CRL signer ID controls CRL signature verification. The caller supplies
the available CRLs and verification time.

Set `require_chain_revocation=True` to check the status of each used
intermediate and CRL signer below the explicit trust anchor. The verifier
associates the chain selected by OpenSSL with the supplied DER certificates.
If two candidate certificates share a rendered name used in the path,
the check requires an unambiguous path. Each status check consumes an
authenticated snapshot issued by the exact validated parent certificate.
Processing proceeds from the anchor toward the endpoints. This provides
an acyclic evidence chain and detects missing or stale evidence, revocation,
and a signer offering its own CRL as evidence of its status. Tests include
SM2 and RSA paths, an unused intermediate, and a valid CRL signer on a
different branch from a revoked target intermediate. This strict setting covers direct upstream CRLs
for path status. The target assessment also supports authenticated indirect
CRLs under the same anchor.
[RFC 5280 §6.1](https://www.rfc-editor.org/rfc/rfc5280#section-6.1) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### Signed attributes and algorithm parameters

Section 8 on printed pages 4 and 5 declares the field `signedAttrs [0]
IMPLICIT SignedAttributes` and names the DER encoding of `signedAttrs`
as the signing input. X.690 §8.14 gives that field the constructed `[0]`
tag (`A0`). The verifier uses the field's exact DER bytes on this reading.
RFC 5652 §5.4 explicitly specifies universal `SET` (`31`)
for CMS; the verifier supports that preimage when explicitly selected.
OpenSSL witnesses check both directions of rejection with identical
attribute members, and pin the default in attached and detached mode.
Section 8 defines the `messageDigest` value and its SM3 binding. The
project identifies this attribute with PKCS #9 `1.2.840.113549.1.9.4`,
as documented in RFC 2985 Appendix A and RFC 5652 §11.2. Sections 6.9
and 8 name the attribute and leave its numerical OID unstated. For each
signer with `signedAttrs`, the project requires exactly one instance
containing exactly one primitive 32-octet DER `OCTET STRING`. Signature
verification compares it to SM3 of the original content octets. The test
matrix signs the correct digest, a neighboring OID, a digest carried
only in `unsignedAttrs`, a digest of the DER content wrapper, and a
33-octet digest under both preimages, with attached and detached content.
It also pins the built-in schema when the caller supplies schemas.

Section 6.2 points to the optional, algorithm-defined `parameters` field
of GB/T 20518-2018 §5.2.2. Its SM2 no-parameter statement appears in the
certificate signature algorithm rules. GB/T 35275-2026 §§6.3–6.4 refer
to GB/T 33560 for the OIDs. The 2017 and 2026 identifier tables give the
OID and its meaning. The envelope uses `.401` or `.401.1` for SM3 and
`.301.1` for SM2-1 under the `1.2.156.10197.1` arc. Tests reject both the
keyed SM3 (`.401.2`) and SM2-with-SM3 (`.501`) substitutes in their
respective envelope contexts. GB/T 35275-2026 took effect on 2026-11-01.
GB/T 33560-2026 takes effect on 2026-12-01.
Appendix A.1 is informative and its historical envelope contains NULL
for both occurrences of unkeyed SM3 and the SM2-1 identifier. The project
enforces the following receive table. Each accepted form is the entire
encoding following the OID in its `AlgorithmIdentifier`.

| Field | Algorithm OID | Accepted parameters |
| --- | --- | --- |
| `digestAlgorithms`, `SignerInfo.digestAlgorithm` | `1.2.156.10197.1.401` | Absent or the two DER octets `05 00` |
| `digestAlgorithms`, `SignerInfo.digestAlgorithm` | `1.2.156.10197.1.401.1` | Absent or the two DER octets `05 00` |
| `SignerInfo.signatureAlgorithm` | `1.2.156.10197.1.301.1` | Absent or the two DER octets `05 00` |

The tests cover all 64 accepted combinations of these fields and content
modes, and check seven excluded parameter encodings for every field/OID
pair. These include an OCTET STRING, INTEGER, truncated and constructed
NULL, a NULL with a payload, nonminimal length and a duplicate NULL. The
published sources define the algorithm identifiers and the optional
field, and provide an informative example of NULL. The exact two-form
receive table and the numerical attribute identifier are project
interoperability decisions. This evidence supports acceptance of the
implemented profile.
[GB/T 35275-2026](https://std.samr.gov.cn/gb/search/gbDetailedCNF?id=511EBC5968889318E06397BE0A0AFBD5) ·
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[GB/T 33560-2017](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=252CF0F72A7BE339A56DEA7D774E8994) ·
[GB/T 33560-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=9BF813CEEAFB58A19534FF861465D8FD) ·
[ITU-T X.690 §8.14](https://www.itu.int/rec/T-REC-X.690/en) ·
[PKCS #9, RFC 2985 Appendix A](https://www.rfc-editor.org/rfc/rfc2985.html#appendix-A) ·
[RFC 5652 §5.4](https://www.rfc-editor.org/rfc/rfc5652#section-5.4) ·
[RFC 5652 §11.2](https://www.rfc-editor.org/rfc/rfc5652#section-11.2)

## Appendix A.1 audit

The published example shows two unkeyed SM3 identifiers
(`1.2.156.10197.1.401.1`) with DER NULL on printed pages 11 and 16 and
an SM2-1 identifier (`1.2.156.10197.1.301.1`) with DER NULL on page 16.
The outer version is 1 and the embedded message is 24 bytes. The
example's inner version is 1 at offset 860 on printed page 15. Section 8
table 3 gives the normative inner version as 2.
[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

The fixture pins a published hexadecimal transcription of the version-1
example, checks the field offsets against the official listing, and replays
its signature in OpenSSL over the 24 embedded bytes using the certificate's
public key and the explicitly configured SM2 user ID. The valid signature
provides a historical interoperability witness. The fixture confirms that
both signature algorithm identifiers of the embedded certificate contain
explicit DER NULL. The standalone version test checks the normative version
rule with a separate, valid v2 payment envelope.
[Hexadecimal transcription](https://www.gm7.org/archives/108338)

### Daybreak regression evidence

| Finding | Witnesses exercised by the normal verification runner |
| --- | --- |
| `acf_69f5661c16d250ae2ea735495e86ed2a` | Same-name signer keys have separate freshness scopes. Direct coverage follows the selected issuer key. Delegation uses issuers on the target path. |
| `acf_c7cfda72b09a4d8273163aebceabe2e4` | Format, general and payment entry points enforce byte, element, depth and collection boundaries. Embedded extension values charge the same budget. The over-budget signed attributes case verifies that hashing has yet to start. |

The test runner checks both entries in the [executable traceability
table](test_signed_data_acceptance.py).
