REQUIRE BSV

( Reusable one-input, one-successor PELS fragment for a BIP143 ALL preimage. )
( The state is supplied by the executing lock. Its layout is a push of five )
( bytes, OP_CODESEPARATOR, then the continuing code. The caller must bind )
( this same full preimage against the current input with native CHECKSIG. )

: pels-assert-one-input ( script -- script )
    ( Runtime: preimage -- preimage. )
    op-dup 68 bsv-num op-split op-nip 36 bsv-num op-split op-drop op-hash256
    op-over op-4 op-split op-nip 32 bsv-num op-split op-drop op-equalverify
;

: pels-script-size ( script -- script )
    ( Runtime: length -- canonical CompactSize for supported Script lengths. )
    op-dup 253 bsv-num op-lessthan op-if
        op-2 op-num2bin op-1 op-split op-drop
    op-else
        op-dup 65536 bsv-num op-lessthan op-if
            op-3 op-num2bin op-2 op-split op-drop
            bytes-hex fd bsv-push op-swap op-cat
        op-else
            op-4 op-num2bin bytes-hex fe bsv-push op-swap op-cat
        op-endif
    op-endif
;

: pels-read-script-code ( script -- script )
    ( Runtime: BIP143 header and scriptCode blob -- scriptCode. )
    104 bsv-num op-split op-nip
    op-dup op-1 op-split op-drop
    op-dup bytes-hex fd bsv-push op-equal op-if
        op-drop op-3
    op-else
        bytes-hex fe bsv-push op-equal op-if op-5 op-else op-1 op-endif
    op-endif
    op-split op-tuck op-size op-nip pels-script-size op-equalverify
;

: pels-assert-all ( script -- script )
    ( Runtime: BIP143 trailer -- trailer. )
    op-dup 48 bsv-num op-split op-nip bytes-hex 41000000 bsv-push op-equalverify
;

: pels-save-output-hash ( script -- script )
    ( Runtime: BIP143 trailer -- trailer | alt: hashOutputs. )
    op-dup 12 bsv-num op-split op-nip 32 bsv-num op-split op-drop op-toaltstack
;

: pels-read-output-context ( script -- script )
    ( Runtime: state preimage -- state prev-amount | alt: hashOutputs code. )
    pels-assert-one-input
    op-size 52 bsv-num op-sub op-split
    pels-assert-all pels-save-output-hash
    op-8 op-split op-drop op-swap
    pels-read-script-code
    op-toaltstack op-bin2num
;

: pels-check-successor-output ( script -- script )
    ( Runtime: successor-state-bytes successor-amount-bytes -- nothing. )
    op-fromaltstack op-rot
    bytes-hex 05 bsv-push op-swap op-cat
    bytes-hex ab bsv-push op-cat op-swap op-cat
    op-size pels-script-size op-swap op-cat op-cat
    op-hash256 op-fromaltstack op-equalverify
;

: pels-assert-successor ( script script -- script )
    ( Build arguments: prefix and a state/amount rule. )
    ( Rule runtime: state prev-amount -- successor-state-bytes successor-amount-bytes. )
    swap pels-read-output-context swap bsv-cat-code pels-check-successor-output
;
