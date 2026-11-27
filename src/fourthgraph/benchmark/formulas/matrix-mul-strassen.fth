REQUIRE BSV
( Same input and output ranges as matrix-mul, including the widened intermediates. )
range: matrix-entry script-int -57896044618658097711785492504343953926634992332820282019728792003956564819968 57896044618658097711785492504343953926634992332820282019728792003956564819968 ;
range: matrix-product script-int -214524926879081553593184399971293538039669853129478294043576983099548224481176751628829988770670454843040509730983776813660062124991145119142938384097345536 214524926879081553593184399971293538039669853129478294043576983099548224481176751628829988770670454843040509730983776813660062124991145119142938384097345536 ;

formula: matrix-product-2x2 ( matrix-entry matrix-entry matrix-entry matrix-entry matrix-entry matrix-entry matrix-entry matrix-entry -- matrix-product matrix-product matrix-product matrix-product )
    {: a b c d e f g h :}
    a d int+ e h int+ int* let m1
    c d int+ e int* let m2
    a f h int- int* let m3
    d g e int- int* let m4
    a b int+ h int* let m5
    c a int- e f int+ int* let m6
    b d int- g h int+ int* let m7

    m1 m4 int+ m5 int- m7 int+
    m3 m5 int+
    m2 m4 int+
    m1 m2 int- m3 int+ m6 int+
;
