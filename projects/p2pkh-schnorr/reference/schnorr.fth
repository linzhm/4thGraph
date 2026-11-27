REQUIRE BSV

( P2PKH-Schnorr payment example. Transaction policy lives in this source. )
REQUIRE stdlib/script-fragments.fth
REQUIRE stdlib/secp256k1.fth
REQUIRE stdlib/bip340.fth

( Transaction authorization and scriptCode. The five NOPs are the Schnorr domain marker. )
: schnorr-tag ( script -- script ) op-nop op-nop op-nop op-nop op-nop ;
: schnorr-ordinary-code ( script -- script ) schnorr-tag op-endif op-checksig ;
: schnorr-companion-code ( script -- script )
    schnorr-tag op-if op-checksigverify op-else op-codeseparator schnorr-ordinary-code
;

: check-sighash ( script -- script )
    ( Require ForkID, allow Chronicle and ANYONECANPAY, and select ALL, NONE or SINGLE. )
    op-1 op-split bytes-hex 000000 bsv-push op-equalverify
    op-dup bytes-hex 5c bsv-push op-and bytes-hex 40 bsv-push op-equalverify
    op-dup op-3 op-and op-verify
;

: check-forkid-shape ( script script -- script )
    ( The argument is the expected scriptCode, which has a one-byte CompactSize. )
    swap op-over op-size over script-size 157 + bsv-num op-numequalverify
    104 bsv-num op-split op-nip over script-size 1+ bsv-num op-split op-drop
    swap dup script-size cell>byte swap script>bytes bytes-cat bsv-push op-equalverify
;

: check-companion ( script -- script )
    ( Unpaired SINGLE uses BIP143 0x43 or 0xc3 and a zero hashOutputs. )
    op-fromaltstack op-dup op-toaltstack op-dup bytes-hex 43 bsv-push op-equal op-swap
    bytes-hex c3 bsv-push op-equal op-boolor op-verify
    bsv-empty schnorr-companion-code check-forkid-shape
    op-over bsv-empty schnorr-companion-code script-size 117 + bsv-num op-split op-nip
    32 bsv-num op-split op-drop
    bytes-hex 0000000000000000000000000000000000000000000000000000000000000000 bsv-push op-equalverify
;

: authorize-preimage ( script -- script )
    ( Input: preimage packedWitness mode. Save the mode and binding sighash on the altstack. )
    op-depth op-3 op-numequalverify op-dup op-0 op-equal op-over op-1 op-equal op-boolor op-verify
    op-dup op-toaltstack 2 script-pick-depth op-size op-4 op-sub op-split op-nip check-sighash
    op-toaltstack op-if check-companion
    op-else
      op-fromaltstack op-dup op-toaltstack bytes-hex 20 bsv-push op-and
      bytes-hex 20 bsv-push op-equal op-notif
        bsv-empty schnorr-ordinary-code check-forkid-shape
      op-endif
    op-endif
;

: binding-public-key ( script -- script )
    bytes-hex 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push
;

: binding-der ( script -- script )
    ( Native ECDSA binding uses d=k=1, r=Gx and low-S from the supplied digest. )
    script-uint256be secp256k1-gx op-add secp256k1-order op-mod op-dup op-verify
    op-dup secp256k1-order op-swap op-sub op-min op-size op-toaltstack
    32 bsv-num op-num2bin script-reverse32 32 bsv-num op-fromaltstack op-sub op-split op-nip
    op-size op-tuck op-toaltstack op-cat
    bytes-hex 022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802 bsv-push
    op-swap op-cat op-fromaltstack 36 bsv-num op-add
    bytes-hex 30 bsv-push op-swap op-cat op-swap op-cat
;

: bind-current-input ( script -- script )
    binding-der op-fromaltstack op-cat binding-public-key
    op-fromaltstack op-dup op-if
      op-toaltstack op-over op-size op-1sub op-split op-nip bytes-hex 20 bsv-push op-or
      ( DER for the unpaired OTDA SINGLE constant digest 01 followed by 31 zero bytes. )
      bytes-hex 3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207abe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
      bsv-push op-swap op-cat binding-public-key op-fromaltstack
    op-endif
    op-codeseparator schnorr-companion-code
;

: schnorr-lock-prefix ( script -- script )
    authorize-preimage
    op-swap op-hash256 op-dup op-toaltstack op-swap
    op-size 160 bsv-num op-numequalverify 32 bsv-num op-split 32 bsv-num op-split 64 bsv-num op-split
    3 script-pick-depth op-hash160
;

: schnorr-check-owner ( script bytes -- script )
    swap schnorr-lock-prefix swap bsv-push op-equalverify ;

: schnorr-check-signature ( script -- script ) bip340-verify op-verify ;

: schnorr-lock ( script bytes -- script )
    schnorr-check-owner
    schnorr-check-signature
    op-fromaltstack bind-current-input
;

( The wallet supplies the approved preimage and the external signer's verified witness. )
: push-data ( bytes -- script ) bsv-empty swap bsv-push ;
: push-number ( cell -- script ) bsv-empty swap bsv-num ;
: pack-witness ( bytes bytes bytes bytes -- bytes ) bytes-cat bytes-cat bytes-cat ;

: schnorr-unlock ( bytes cell bytes bytes bytes bytes -- script )
    ( Arguments: preimage mode px py signature ry. Emit three pushes in lock input order. )
    pack-witness push-data swap push-number bsv-cat-code
    swap push-data swap bsv-cat-code
;
