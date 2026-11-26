( Runtime words for the R1 four-bit window. Bounds are half-open. )
range: r1-scalar script-int 0 $ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 ;
range: r1-digit script-int 0 16 ;
range: r1-q-depth script-int 5 51 ;
range: r1-g-depth script-int 53 99 ;

bsv-effect: window-digit r1-scalar -- r1-digit ;
: window-digit 16 cell>int int-rem ;

bsv-effect: q-pick-depth r1-digit -- r1-q-depth ;
: q-pick-depth 3 cell>int int* 50 cell>int swap int- ;

bsv-effect: g-pick-depth r1-digit -- r1-g-depth ;
: g-pick-depth 3 cell>int int* 98 cell>int swap int- ;

( The remainder is deliberately redundant so the two build costs can be compared. )
bsv-effect: q-depth-probe r1-digit -- r1-q-depth ;
: q-depth-probe q-pick-depth 64 cell>int int-rem ;

bsv-effect: checked-q-depth script-int -- r1-q-depth ;
: checked-q-depth check-range r1-digit q-depth-probe ;
