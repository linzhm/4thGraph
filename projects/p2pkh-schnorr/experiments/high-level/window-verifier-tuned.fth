REQUIRE BSV
REQUIRE batch-witness.fth

( The shared decoder has already checked the field widths and emits unsigned integers. )
: require-coordinate-bound ( script-int script-int -- )
    swap int< verify
;

layout: coordinate-bounds ( px:script-int py:script-int rx:script-int ry:script-int s:script-int e:script-int p:script-int --
                           px py rx ry s e p p px p py p rx p ry )
layout: public-curve ( px:script-int py:script-int rx:script-int ry:script-int s:script-int e:script-int p:script-int --
                      rx ry px py s e p p px py )
layout: witness-parity ( rx:script-int ry:script-int px:script-int py:script-int s:script-int e:script-int p:script-int --
                         rx ry px py s e p py ry )
layout: challenge-input ( rx:script-int ry:script-int px:script-int py:script-int s:script-int e:script-int p:script-int --
                          rx ry px py p s e )
layout: tuned-model-input ( rx:script-int ry:script-int px:script-int py:script-int p:script-int
                            s:script-int e:script-int -- s e p rx ry px py )
layout: tuned-model-result ( s:script-int e:script-int p:script-int rx:script-int ry:script-int
                             px:script-int py:script-int -- rx ry px py p s e )

( Both decoded ordinates are unsigned. Their remainders are 0 or 1. )
: require-even-pair ( script-int script-int -- )
    2 cell>int int-rem swap 2 cell>int int-rem int+ 0 cell>int int= verify
;

: reduce-challenge-with-order ( script-int script-int script-int -- script-int script-int script-int )
    ( s hash n -> s k n, where 0 <= s < n and k = n - hash mod n. )
    rot 2dup swap int< verify
    swap rot over int-rem
    over swap int- swap
;

: prepare-tuned ( bytes bytes bytes bytes bytes --
                  script-int script-int script-int script-int script-int script-int script-int )
    ( Carry the same field prime through range checks, the curve equation, and the model map. )
    decode-witness field-prime coordinate-bounds
    require-coordinate-bound require-coordinate-bound require-coordinate-bound require-coordinate-bound
    public-curve check-curve
    witness-parity require-even-pair
    challenge-input
;

: check-tuned-nonce ( script-int script-int script-int script-int script-int script-int -- )
    nonce-residuals 0 cell>int int= verify 0 cell>int int= verify
    0 cell>int int= 0= verify
;

lock: window-bip340-tuned ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-tuned
    tuned-model-input map-affine-pair tuned-model-result
    ( Keep the order beside k for the GLV split. )
    group-order reduce-challenge-with-order
    secp256k1-joint-mapped-with-order check-tuned-nonce
    1
;
