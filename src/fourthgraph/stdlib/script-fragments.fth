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

: script-repeat-mask-code ( script cell -- script )
    ( Each emitted DUP CAT doubles the number of copies of the seed. )
    bsv-empty op-dup op-cat swap script-append-repeated
;

: script-repeat-mask ( bytes cell -- script )
    bsv-empty rot bsv-push swap script-repeat-mask-code
;

: script-block-mask ( cell cell -- script )
    ( Build alternating zero and FF blocks. Arguments are block width and doublings. )
    bsv-empty op-0 rot bsv-num op-num2bin op-dup op-invert op-cat swap script-repeat-mask-code
;

: script-swap-bit-groups ( script cell script -- script )
    ( A mask selects the lower bits of each pair of groups. XOR the differences into both groups. )
    swap rot op-dup over bsv-num op-rshift op-over op-xor
    rot bsv-cat-code op-and op-tuck op-xor op-swap swap bsv-num op-lshift op-xor
;

: script-le-unsigned ( script -- script ) bytes-hex 00 bsv-push op-cat op-bin2num ;
: script-reverse32 ( script -- script )
    ( Split off the bytes in order, then build the result from the last byte back. )
    bsv-empty op-1 op-split 31 script-append-repeated
    bsv-empty op-swap op-cat 31 script-append-repeated
;
: script-uint256be ( script -- script ) script-reverse32 script-le-unsigned ;

: script-field-byte-swap ( script cell cell cell -- script cell )
    ( Prefix, field count, group width, mask doublings. Preserve the field count. )
    over 8 * swap rot swap script-block-mask
    rot dup rot swap bsv-tile-top
    rot swap 2swap swap 2swap script-swap-bit-groups swap
;

: script-reverse32-fields ( script cell -- script )
    ( The runtime input is exactly that many concatenated 32-byte fields. )
    1 4 script-field-byte-swap
    2 3 script-field-byte-swap
    4 2 script-field-byte-swap
    8 1 script-field-byte-swap
    16 0 script-field-byte-swap drop
;

: script-uint256be-compact ( script -- script )
    1 script-reverse32-fields script-le-unsigned
;

: script-uint256be-fields ( script cell -- script )
    ( Decode consecutive big-endian fields into separate unsigned ScriptNums. )
    dup rot swap script-reverse32-fields
    bsv-empty 32 bsv-num op-split op-swap script-le-unsigned op-swap
    rot 1 - script-append-repeated script-le-unsigned
;
