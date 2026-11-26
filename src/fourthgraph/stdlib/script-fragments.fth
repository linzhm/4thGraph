REQUIRE BSV

( Shared Script construction fragments. op-* words append one Script opcode. )

: script-pick-depth ( script cell -- script )
    dup 0= if drop op-dup else
        dup 1 = if drop op-over else bsv-num op-pick then
    then
;
: script-save-depth ( script cell -- script ) script-pick-depth op-toaltstack ;

: script-append-repeated ( script script cell -- script ) bsv-repeat-code bsv-cat-code ;
: script-drop-pairs ( script cell -- script ) bsv-empty op-2drop swap script-append-repeated ;
: script-restore-items ( script cell -- script ) bsv-empty op-fromaltstack swap script-append-repeated ;

: script-le-unsigned ( script -- script ) bytes-hex 00 bsv-push op-cat op-bin2num ;
: script-reverse32 ( script -- script )
    ( Split off the bytes in order, then build the result from the last byte back. )
    bsv-empty op-1 op-split 31 script-append-repeated
    bsv-empty op-swap op-cat 31 script-append-repeated
;
: script-uint256be ( script -- script ) script-reverse32 script-le-unsigned ;
