REQUIRE r1-baseline.fth
REQUIRE pels-successor.fth

: r1-counter-advance ( script -- script )
    ( Runtime: state -- encoded u32 successor. Increment wraps as in PELS. )
    op-bin2num op-1add bytes-hex 0100000000 bsv-num-be op-mod op-5 op-num2bin
;

: r1-counter-rule ( script -- script )
    ( Runtime: state prev-amount -- successor-state-bytes successor-amount-bytes. )
    1000 bsv-num op-sub op-dup op-0 op-greaterthan op-verify op-8 op-num2bin
    op-swap r1-counter-advance op-swap
;

: r1-counter-check-output ( script -- script )
    ( Runtime: R1 witness state -- R1 witness. Use the supplied full preimage. )
    5 bsv-num op-pick bsv-empty r1-counter-rule pels-assert-successor
;

: r1-counter-read-witness ( script -- script )
    ( This entry supports BIP143 ALL and uses a single separator before the body. )
    op-dup op-0 op-numequalverify
    r1-save-selector-and-inverse op-drop
    r1-check-witness-widths r1-check-owner
    r1-save-authorization-digest
    r1-unpack-r1-inputs op-drop r1-check-r1-fields
    r1-check-inverse
;

: r1-counter-bind-input ( script -- script )
    ( Authenticate the same digest used for R1 with the counter scriptCode. )
    op-fromaltstack r1-k1-bind-digest
    op-fromaltstack op-drop op-checksig
;

: r1-counter-body ( script -- script )
    r1-counter-check-output
    r1-counter-read-witness
    r1-baseline-verify-r1
    r1-counter-bind-input
;

: r1-baseline-counter ( script bytes -- script )
    ( The builder supplies five little-endian state bytes. )
    bsv-push op-codeseparator r1-counter-body
;
