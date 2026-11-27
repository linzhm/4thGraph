REQUIRE BSV

( Homogeneous projective model change. The caller supplies the positive prime p
  and u^2, u^3 for the forward or inverse direction. Z is unchanged. )
: weierstrass-scale ( script-int script-int script-int script-int script-int script-int --
                     script-int script-int script-int script-int )
    ( p X Y Z u2 u3 -- p X' Y' Z )
    int-roll-4 int-roll-2 int* int-pick-4 int-rem
    int-roll-3 int-roll-2 int* int-pick-3 int-rem rot
;
