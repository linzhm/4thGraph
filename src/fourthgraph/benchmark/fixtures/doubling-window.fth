REQUIRE stdlib/secp256k1.fth

: double-with-checkpoint ( script -- script )
    ( Input p X Y Z. Keep the exact first-round coordinates as an observable checkpoint. )
    1 secp256k1-double-window
    op-dup op-toaltstack op-over op-toaltstack op-2 op-pick op-toaltstack
    9 secp256k1-double-window
    ( Output p, the final X Y Z, then the first X Y Z. )
    op-fromaltstack op-fromaltstack op-fromaltstack
;
