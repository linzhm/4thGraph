REQUIRE r1-math-point.fth

: r1-double-accumulator ( script -- script )
    op-toaltstack op-3dup r1-point-add op-fromaltstack
;

: r1-test-scalar-bit ( script -- script )
    ( Runtime invariant: scalar base accumulator bit-mask. )
    7 bsv-num op-pick op-over op-div op-2 op-mod
;

: r1-add-base-to-accumulator ( script -- script )
    op-toaltstack
    5 bsv-num op-pick 5 bsv-num op-pick 5 bsv-num op-pick
    r1-point-add op-fromaltstack
;

: r1-scalar-bit ( script -- script )
    r1-double-accumulator
    r1-test-scalar-bit op-if r1-add-base-to-accumulator op-endif
    op-2 op-div
;

: r1-scalar-multiply ( script -- script )
    ( Runtime: scalar point -- product. A fixed expansion of textbook double and add. )
    r1-infinity
    bytes-hex 8000000000000000000000000000000000000000000000000000000000000000 bsv-num-be
    bsv-empty r1-scalar-bit 256 bsv-repeat-code bsv-cat-code
    op-drop
    bsv-empty r1-discard-before-point 4 bsv-repeat-code bsv-cat-code
;
