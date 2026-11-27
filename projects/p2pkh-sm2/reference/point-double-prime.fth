REQUIRE point-ranges.fth

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
