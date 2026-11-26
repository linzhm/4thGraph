REQUIRE BSV

( Compute a wrapped counter and build a P2PKH lock from a recipient hash. )
REQUIRE stdlib/u32.fth
REQUIRE stdlib/p2pkh.fth

: advance-and-pay ( u32 bytes -- u32 bytes ) swap u32-inc swap p2pkh-lock ;
