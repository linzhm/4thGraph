REQUIRE BSV

( Script remainder is signed. Every projective coordinate has magnitude below the field prime. )
range: field script-int 115792089237316195423570985008687907853269984665640564039457584007908834671663 115792089237316195423570985008687907853269984665640564039457584007908834671664 ;
range: coord script-int -115792089237316195423570985008687907853269984665640564039457584007908834671662 115792089237316195423570985008687907853269984665640564039457584007908834671663 ;
range: scalar script-int 0 115792089237316195423570985008687907853269984665640564039457584007913129639936 ;

( Complete homogeneous point addition on y^2 = x^3 + 7, including doubling and infinity. )
formula: add-points ( field coord coord coord coord coord coord -- field coord coord coord )
    {: p x1 y1 z1 x2 y2 z2 :}
    x1 x2 int* let xx
    y1 y2 int* let yy
    z1 z2 int* let zz
    x1 y1 int+ x2 y2 int+ int* xx int- yy int- let xy
    y1 z1 int+ y2 z2 int+ int* yy int- zz int- let yz
    x1 z1 int+ x2 z2 int+ int* xx int- zz int- let xz
    21 zz int* let bzz
    21 xz int* let bxz
    3 xx int* let triple-x
    yy bzz int+ let plus
    yy bzz int- let minus

    p
    xy minus int* yz bxz int* int- p int-rem
    minus plus int* triple-x bxz int* int+ p int-rem
    yz plus int* xy triple-x int* int+ p int-rem
;

formula: curve-residual ( field coord coord -- coord )
    {: p x y :}
    y y int* x x int* x int* 7 int+ int- p int-rem
;

formula: nonce-residuals ( coord coord field coord coord coord -- coord coord coord )
    {: r ry p x y z :}
    z
    r z int* x int- p int-rem
    ry z int* y int- p int-rem
;

( Keep the state needed by the other scalar and expose this bit's operands. )
formula: fixed-bit ( scalar coord coord coord coord scalar scalar field coord coord coord --
                     scalar coord coord coord coord scalar scalar coord coord scalar field coord coord coord )
    {: h gx gy px py s k p x y z :}
    h gx gy px py k  h gx gy s p x y z
;

formula: variable-bit ( scalar coord coord coord coord scalar scalar field coord coord coord --
                        scalar coord coord coord coord scalar scalar coord coord scalar field coord coord coord )
    {: h gx gy px py k s p x y z :}
    h gx gy px py s  h px py k p x y z
;

formula: expose-scalar ( scalar coord coord scalar field coord coord coord --
                         coord coord field coord coord coord scalar scalar )
    {: h bx by k p x y z :}
    bx by p x y z h k
;

formula: with-base ( coord coord field coord coord coord scalar --
                     scalar field coord coord coord coord coord )
    {: bx by p x y z k :}
    k p x y z bx by
;

formula: without-base ( coord coord field coord coord coord scalar -- scalar field coord coord coord )
    {: bx by p x y z k :}
    k p x y z
;

formula: discard-scalar-state ( scalar coord coord coord coord scalar scalar field coord coord coord --
                                field coord coord coord )
    {: h gx gy px py s k p x y z :}
    p x y z
;
