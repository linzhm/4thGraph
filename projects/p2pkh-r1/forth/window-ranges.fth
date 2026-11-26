REQUIRE BSV

( Runtime words for the R1 four-bit window. Bounds are half-open. )
range: r1-scalar script-int 0 $ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 ;
range: r1-digit script-int 0 16 ;
range: r1-q-depth script-int 5 51 ;
range: r1-g-depth script-int 53 99 ;

: window-digit ( r1-scalar -- r1-digit ) 16 cell>int int-rem ;

: q-pick-depth ( r1-digit -- r1-q-depth ) 3 cell>int int* 50 cell>int swap int- ;

: g-pick-depth ( r1-digit -- r1-g-depth ) 3 cell>int int* 98 cell>int swap int- ;

( The remainder is deliberately redundant so the two build costs can be compared. )
: q-depth-probe ( r1-digit -- r1-q-depth ) q-pick-depth 64 cell>int int-rem ;

: checked-q-depth ( script-int -- r1-q-depth ) check-range r1-digit q-depth-probe ;
