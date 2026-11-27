REQUIRE BSV
REQUIRE point-double-prime.fth

( The verifier copies its field constants below the accumulator once. )
( The projective right operand comes from the public-key table. )
formula: sm2-window-add-projective ( three-b field-prime coordinate coordinate coordinate coordinate coordinate coordinate -- three-b field-prime coordinate coordinate coordinate )
    {: b p x1 y1 z1 x2 y2 z2 :}
    x1 x2 int* let xx
    y1 y2 int* let yy
    z1 z2 int* let zz
    x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
    x1 z1 int+ x2 z2 int+ int* xx int- zz int- let xz
    y1 z1 int+ y2 z2 int+ int* yy int- zz int- let yz

    -3 xz int* b zz int* int+ let h
    yy h int- let minus
    yy h int+ let plus
    -3 zz int* let azz
    3 xx int* azz int+ let t
    b xz int* 3 xx azz int- int* int- let k

    b p
    xy minus int* yz k int* int- p int-rem
    minus plus int* t k int* int+ p int-rem
    yz plus int* xy t int* int+ p int-rem
;

( The fixed generator table provides affine pairs with Z2 = 1. )
formula: sm2-window-add-affine ( three-b field-prime coordinate coordinate coordinate coordinate coordinate -- three-b field-prime coordinate coordinate coordinate )
    {: b p x1 y1 z1 x2 y2 :}
    x1 x2 int* let xx
    y1 y2 int* let yy
    x1 y2 int* y1 x2 int* int+ let xy
    x1 z1 x2 int* int+ let xz
    y1 z1 y2 int* int+ let yz

    -3 xz int* b z1 int* int+ let h
    yy h int- let minus
    yy h int+ let plus
    -3 z1 int* let azz
    3 xx int* azz int+ let t
    b xz int* 3 xx azz int- int* int- let k

    b p
    xy minus int* yz k int* int- p int-rem
    minus plus int* t k int* int+ p int-rem
    yz plus int* xy t int* int+ p int-rem
;

: sm2-window-double-five ( script -- script )
    ( The subgroup has odd order, so a nonzero point stays finite. )
    op-dup op-0notequal op-if
        bsv-empty sm2-double-with-prime 5 bsv-repeat-code bsv-cat-code
    op-endif
;
