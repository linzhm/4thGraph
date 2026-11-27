REQUIRE BSV

( Advance the state and preserve the executing code in the successor. )
REQUIRE stdlib/u32.fth
pels-amount: witness ;
: advance ( u32 -- u32 ) u32-inc ;
