REQUIRE BSV

( Homogeneous formulas for a = -3, as used by the R1 project. )
( The surrounding SM2 verifier supplies the field prime and 3b at stack depths )
( measured from the bottom. Every coordinate is a signed residue. )
range: coordinate script-int
    $-fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe
    $fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff ;
range: field-prime script-int
    $fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
    $fffffffeffffffffffffffffffffffffffffffff000000010000000000000000 ;
range: three-b script-int
    $7abdefdbd8de1a9ce80fdae36e2f1cf7dac69ddf4102aeb8993637c3e8bc2bb9
    $7abdefdbd8de1a9ce80fdae36e2f1cf7dac69ddf4102aeb8993637c3e8bc2bba ;

formula: sm2-double-finite ( coordinate coordinate coordinate -- coordinate coordinate coordinate )
    {: x y z :}
    3 x z int- x z int+ int* int* let w
    2 y z int* int* let s
    y s int* let r
    2 x r int* int* let b
    w w int* 2 b int* int- let h

    h s int* int-from-bottom 0 field-prime int-rem
    b h int- w int* 2 r r int* int* int- int-from-bottom 0 field-prime int-rem
    s s int* s int* int-from-bottom 0 field-prime int-rem
;

formula: sm2-add-kernel ( coordinate coordinate coordinate coordinate coordinate coordinate -- coordinate coordinate coordinate )
    {: x1 y1 z1 x2 y2 z2 :}
    x1 x2 int* let xx
    y1 y2 int* let yy
    z1 z2 int* let zz
    x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
    x1 z1 int+ x2 z2 int+ int* xx int- zz int- let xz
    y1 z1 int+ y2 z2 int+ int* yy int- zz int- let yz

    -3 xz int* int-from-bottom 1 three-b zz int* int+ let h
    yy h int- let minus
    yy h int+ let plus
    -3 zz int* let azz
    3 xx int* azz int+ let t
    int-from-bottom 1 three-b xz int* 3 xx azz int- int* int- let k

    xy minus int* yz k int* int- int-from-bottom 0 field-prime int-rem
    minus plus int* t k int* int+ int-from-bottom 0 field-prime int-rem
    yz plus int* xy t int* int+ int-from-bottom 0 field-prime int-rem
;

: sm2-double-kernel ( script -- script )
    ( Preserve the coordinates of a point at infinity. )
    op-dup op-0notequal op-if
        sm2-double-finite
    op-endif
;

formula: sm2-double-with-prime ( field-prime coordinate coordinate coordinate -- field-prime coordinate coordinate coordinate )
    {: p x y z :}
    3 x z int- x z int+ int* int* let w
    2 y z int* int* let s
    y s int* let r
    2 x r int* int* let b
    w w int* 2 b int* int- let h

    p
    h s int* p int-rem
    b h int- w int* 2 r r int* int* int- p int-rem
    s s int* s int* p int-rem
;

: sm2-double-window-kernel ( script -- script )
    ( SM2 has odd group order. Doubling a finite point keeps it finite. )
    op-dup op-0notequal op-if
        ( Copy p from the bottom and put it below X Y Z for all five calls. )
        op-depth op-1sub op-pick op-swap op-2swap op-rot
        bsv-empty sm2-double-with-prime 5 bsv-repeat-code bsv-cat-code
        op-3 op-roll op-drop
    op-endif
;
