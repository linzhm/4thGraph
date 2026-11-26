( Verify the same public transition by direct Script or a circuit proof. )
REQUIRE stdlib/u32.fth
REQUIRE stdlib/verify.fth

: decide ( u32 -- route ) 20 cell>u32 u32< if route-review else route-settle then ;

relation: u32-inc decide ;
