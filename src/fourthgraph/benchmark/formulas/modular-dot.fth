REQUIRE BSV

range: sample script-int -2147483648 2147483648 ;
range: modulus script-int 257 8380418 ;
range: residue script-int -8380416 8380417 ;

formula: modular-accumulate ( sample sample sample sample sample modulus -- residue )
    {: a b x y offset m :}
    a x int* y a int* int+
    b x int* y b int* int-
    int+
    1729 3329 int* 256 int+ int+
    offset int+
    m int-rem m int-rem
;
