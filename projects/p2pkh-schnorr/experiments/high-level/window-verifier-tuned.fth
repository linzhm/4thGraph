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
layout: tuned-model-input ( rx:script-int ry:script-int px:script-int py:script-int p:script-int s:script-int k:script-int --
                            s k p rx ry px py )
layout: tuned-model-result ( s:script-int k:script-int p:script-int rx:script-int ry:script-int
                             px:script-int py:script-int -- rx ry px py s k p )

: require-even ( script-int -- )
    2 cell>int int-rem 0 cell>int int= verify
;

: prepare-tuned ( bytes bytes bytes bytes bytes --
                  script-int script-int script-int script-int script-int script-int script-int )
    ( Carry the same field prime through range checks, the curve equation, and the model map. )
    decode-witness field-prime coordinate-bounds
    require-coordinate-bound require-coordinate-bound require-coordinate-bound require-coordinate-bound
    public-curve check-curve
    witness-parity require-even require-even
    challenge-input swap dup group-order int< verify swap group-order int-rem group-order swap int-
;

: check-tuned-nonce ( script-int script-int script-int script-int script-int script-int -- )
    nonce-residuals 0 cell>int int= verify 0 cell>int int= verify
    0 cell>int int= 0= verify
;

lock: window-bip340-tuned ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-tuned
    tuned-model-input map-affine-pair tuned-model-result
    secp256k1-joint-mapped-point check-tuned-nonce
    1
;
