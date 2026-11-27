REQUIRE pels-verify.fth

: draft-tag ( -- bytes ) bytes-hex 0300000000 ;
: ready-tag ( -- bytes ) bytes-hex 0900000000 ;

: next-status ( script -- script )
    ( Runtime: current-tag -- next-tag. )
    op-dup draft-tag bsv-push op-equal op-if
        op-drop ready-tag bsv-push
    op-else
        ready-tag bsv-push op-equalverify draft-tag bsv-push
    op-endif
;

: status-rule ( script -- script )
    ( Runtime: current-tag prev-amount -- next-tag next-amount-bytes. )
    op-8 op-num2bin op-swap next-status op-swap
;

: status-lock ( script bytes -- script )
    bsv-push op-codeseparator
    bsv-empty status-rule pels-verify op-drop op-1
;
