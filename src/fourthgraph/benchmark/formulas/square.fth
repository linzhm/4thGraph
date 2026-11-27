REQUIRE BSV
range: small script-int 0 11 ;
range: squared script-int 0 101 ;
formula: square ( small -- squared )
    {: x :}
    x x int*
;
