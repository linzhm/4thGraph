REQUIRE r1.fth

( Readable R1 reference. All words here construct Script at build time. )
( The runtime contracts below describe only the suffix each word touches. )
( Points use the homogeneous X:Y:Z representation of r1-add-points. )

: r1-baseline-double ( script -- script )
    ( Runtime: R -- 2R. Use the same complete addition for every point. )
    op-3dup r1-add-points
;

: r1-baseline-test-bit ( script -- script )
    ( Runtime: scalar P R mask -- scalar P R mask bit. )
    7 bsv-num op-pick op-over op-div op-2 op-mod
;

: r1-baseline-add-base ( script -- script )
    ( Runtime: scalar P R mask -- scalar P R+P mask. )
    op-toaltstack
    5 bsv-num op-pick 5 bsv-num op-pick 5 bsv-num op-pick
    r1-add-points
    op-fromaltstack
;

: r1-baseline-step-bit ( script -- script )
    ( Double the accumulator. Add the base when this bit is one. )
    op-toaltstack r1-baseline-double op-fromaltstack
    r1-baseline-test-bit op-if r1-baseline-add-base op-endif
    op-2 op-div
;

: r1-baseline-drop-before-point ( script -- script )
    op-3 op-roll op-drop
;

: r1-baseline-scalar-multiply ( script -- script )
    ( Runtime: scalar P -- scalar*P. Start at infinity and scan all 256 bits. )
    op-0 op-1 op-0
    bytes-hex 8000000000000000000000000000000000000000000000000000000000000000 bsv-num-be
    bsv-empty r1-baseline-step-bit 256 bsv-repeat-code bsv-cat-code
    op-drop
    bsv-empty r1-baseline-drop-before-point 4 bsv-repeat-code bsv-cat-code
;

: r1-baseline-mul2 ( script -- script )
    ( Runtime: p 3b r | alt: ... u v Q.y Q.x -- p 3b r sum-point. )
    op-fromaltstack op-fromaltstack op-fromaltstack op-rot op-rot
    op-1 r1-baseline-scalar-multiply
    op-fromaltstack r1-gx r1-gy op-1 r1-baseline-scalar-multiply
    r1-add-points
;

: r1-baseline-check-x ( script -- script )
    ( Runtime: p 3b r R -- nothing. Check the finite ECDSA result. )
    r1-check-point-start
    4 bsv-num op-pick r1-check-point-low
    3 bsv-num op-pick r1-check-point-high
    op-2drop op-2drop op-2drop
;

: r1-baseline-verify-r1 ( script -- script )
    r1-prepare-scalars
    r1-baseline-mul2
    r1-baseline-check-x
;

: r1-baseline-lock ( script -- script )
    r1-prepare-lock
    r1-baseline-verify-r1
    r1-bind-transaction
;
