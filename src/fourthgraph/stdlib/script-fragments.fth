( Shared Script construction fragments. op-* words append one Script opcode. )

: script-pick-depth ( script cell -- script )
    dup 0= if drop op-dup else
        dup 1 = if drop op-over else bsv-num op-pick then
    then
;
: script-save-depth ( script cell -- script ) script-pick-depth op-toaltstack ;
: script-drop-pairs ( script cell -- script ) bsv-empty op-2drop swap bsv-repeat-code bsv-cat-code ;
: script-restore-items ( script cell -- script ) bsv-empty op-fromaltstack swap bsv-repeat-code bsv-cat-code ;

: script-le-unsigned ( script -- script ) bytes-hex 00 bsv-push op-cat op-bin2num ;
: script-reverse-byte ( script -- script ) op-1 op-split op-swap op-toaltstack ;
: script-append-byte ( script -- script ) op-fromaltstack op-cat ;
: script-reverse32 ( script -- script )
    bsv-empty script-reverse-byte 31 bsv-repeat-code bsv-cat-code
    bsv-empty script-append-byte 31 bsv-repeat-code bsv-cat-code
;
: script-uint256be ( script -- script ) script-reverse32 script-le-unsigned ;
