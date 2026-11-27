REQUIRE BSV
REQUIRE stdlib/script-fragments.fth
REQUIRE stdlib/bip340.fth

: byte-reverse-fields-split ( script cell -- script )
    ( The caller checks the total length. Reverse each 32-byte field in place. )
    1 - dup rot
    bsv-empty 32 bsv-num op-split op-swap script-reverse32 op-swap
    rot script-append-repeated script-reverse32
    bsv-empty op-cat rot script-append-repeated
;

: byte-reverse-six-fields ( script -- script )
    ( The caller has checked that the top item has exactly six 32-byte fields. )
    bip340-reverse-challenge-fields
;

: byte-constant-literal ( script bytes -- script ) bsv-push ;

: byte-constant-repeat ( script bytes cell -- script )
    ( The build arguments are an exact seed and the number of doublings. )
    rot rot bsv-push bsv-empty op-dup op-cat rot script-append-repeated
;
