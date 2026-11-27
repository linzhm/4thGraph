
REQUIRE BSV
range: coordinate script-int -128 128 ;
range: parameter script-int 0 17 ;
range: position script-int -131072 131073 ;
range: tangent script-int -16320 16321 ;

formula: bezier-coordinate ( coordinate coordinate coordinate parameter -- position tangent )
    {: p0 p1 p2 t :}
    16 t int- let u
    u p0 int* t p1 int* int+ let left
    u p1 int* t p2 int* int+ let right
    u left int* t right int* int+
    right left int- 2 int*
;
