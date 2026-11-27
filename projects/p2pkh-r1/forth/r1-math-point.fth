REQUIRE r1-math-field.fth

( Affine points are x y finite. The unique infinity encoding is 0 0 0. )
( The verified P-256 prime and b are the first two bottom stack items. )

formula: r1-curve-equation ( r1-coordinate r1-coordinate -- r1-coordinate )
    {: x y :}
    int-from-bottom 0 r1-field-prime let p
    y y int* x x int* x int* 3 x int* int- int-from-bottom 1 r1-curve-constant int+ int-
    p int-rem p int+ p int-rem
;

formula: r1-add-deltas ( r1-coordinate r1-coordinate r1-coordinate r1-coordinate --
                        r1-coordinate r1-coordinate r1-coordinate r1-coordinate r1-coordinate )
    {: x1 y1 x2 y2 :}
    int-from-bottom 0 r1-field-prime let p
    x1 y1 x2
    y2 y1 int- p int-rem p int+ p int-rem
    x2 x1 int- p int-rem p int+ p int-rem
;

formula: r1-double-deltas ( r1-coordinate r1-coordinate r1-coordinate r1-coordinate --
                           r1-coordinate r1-coordinate r1-coordinate r1-coordinate r1-coordinate )
    {: x1 y1 x2 y2 :}
    int-from-bottom 0 r1-field-prime let p
    x1 y1 x2
    3 x1 x1 int* int* 3 int- p int-rem p int+ p int-rem
    2 y2 int* p int-rem
;

formula: r1-affine-result ( r1-coordinate r1-coordinate r1-coordinate r1-coordinate r1-coordinate --
                           r1-coordinate r1-coordinate )
    {: x1 y1 x2 numerator denominator-inverse :}
    int-from-bottom 0 r1-field-prime let p
    numerator denominator-inverse int* p int-rem let slope
    slope slope int* x1 int- x2 int- p int-rem p int+ p int-rem let result-x
    result-x
    slope x1 result-x int- int* y1 int- p int-rem p int+ p int-rem
;

: r1-infinity ( script -- script )
    op-0 op-0 op-0
;

: r1-discard-before-point ( script -- script )
    op-3 op-roll op-drop
;

: r1-same-x ( script -- script )
    ( Runtime: x1 y1 x2 y2 -- x1 y1 x2 y2 equal-x. )
    op-3 op-pick op-2 op-pick op-numequal
;

: r1-opposite-points ( script -- script )
    r1-same-x op-if
        op-2 op-pick op-over op-add r1-prime op-mod op-0 op-numequal
    op-else op-0 op-endif
;

: r1-add-finite ( script -- script )
    ( Runtime: x1 y1 x2 y2 -- sum. The points are on the curve. )
    r1-opposite-points op-if
        op-2drop op-2drop r1-infinity
    op-else
        r1-same-x op-if r1-double-deltas op-else r1-add-deltas op-endif
        r1-prime op-swap r1-inverse
        r1-affine-result op-1
    op-endif
;

: r1-point-add ( script -- script )
    ( Runtime: P Q -- sum. Each point is valid or infinity. )
    op-dup op-notif
        op-2drop op-drop
    op-else
        op-3 op-pick op-notif
            bsv-empty r1-discard-before-point 3 bsv-repeat-code bsv-cat-code
        op-else
            op-drop op-2 op-roll op-drop r1-add-finite
        op-endif
    op-endif
;
