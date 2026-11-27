
REQUIRE BSV
range: coordinate script-int -128 128 ;
range: parameter script-int 0 17 ;
range: position script-int -131072 131073 ;
range: tangent script-int -16320 16321 ;

formula: bezier-coordinate ( coordinate coordinate coordinate parameter -- position tangent )
    {: p0 p1 p2 t :}
    16 t int- let complement
    p0 complement complement int* int*
    2 p1 int* t int* complement int* int+
    p2 t t int* int* int+

    p1 p0 int- complement int*
    p2 p1 int- t int* int+
    2 int*
;
