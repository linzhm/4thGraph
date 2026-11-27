REQUIRE stdlib/byte-layout.fth

: six-field-mask ( -- bytes )
    ( Six 32-byte fields share a periodic 3-byte mask. )
    bytes-hex 3cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc3693cc369
;

: one-field-mask ( -- bytes )
    bytes-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
;

: convert-fields ( script -- script )
    ( Runtime input and output order: one 32-byte field, then six packed fields. )
    6 reverse-32-fields six-field-mask byte-constant op-xor
    op-swap 1 reverse-32-fields one-field-mask byte-constant op-xor op-swap
;
