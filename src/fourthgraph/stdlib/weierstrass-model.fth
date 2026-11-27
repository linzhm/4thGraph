REQUIRE BSV

range: coord script-int $-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                         $10000000000000000000000000000000000000000000000000000000000000000 ;
range: field script-int 2 $10000000000000000000000000000000000000000000000000000000000000000 ;
range: factor script-int 0 $10000000000000000000000000000000000000000000000000000000000000000 ;

( The zero tests compare the projective point with the affine point in its original model.
  Factors convert the projective numerators before taking the residual modulo the field. )
formula: weierstrass-scaled-residuals ( coord coord field coord coord coord factor factor -- coord coord coord )
    {: rx ry p x y z u2 u3 :}
    z
    x u2 int* rx z int* int- p int-rem
    y u3 int* ry z int* int- p int-rem
;

formula: weierstrass-scaled-residuals-root ( coord coord field coord coord coord factor -- coord coord coord )
    {: rx ry p x y z u :}
    u u int* let u2
    z
    x u2 int* rx z int* int- p int-rem
    y u2 u int* int* ry z int* int- p int-rem
;

( Share factors across two affine points in a single model change. )
formula: weierstrass-scale-pair ( field coord coord coord coord factor factor -- field coord coord coord coord )
    {: p rx ry x y u2 u3 :}
    p
    rx u2 int* p int-rem ry u3 int* p int-rem
    x u2 int* p int-rem y u3 int* p int-rem
;

formula: weierstrass-scale-pair-root ( field coord coord coord coord factor -- field coord coord coord coord )
    {: p rx ry x y u :}
    u u int* let u2
    u2 u int* let u3
    p
    rx u2 int* p int-rem ry u3 int* p int-rem
    x u2 int* p int-rem y u3 int* p int-rem
;
