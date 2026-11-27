REQUIRE stdlib/pels/bip143-all-1in-1out.fth

: expected-output0 ( script -- script )
    ( Retain the state and encode the previous amount in eight wire-order bytes. )
    op-8 op-num2bin
;

: require-output-and-time ( script -- script )
    bsv-empty expected-output0 pels-verify-preimage
    bytes-hex 2a000000 pels-assert-locktime
;

: example-lock ( script bytes -- script )
    bsv-push op-codeseparator require-output-and-time op-drop op-1
;
