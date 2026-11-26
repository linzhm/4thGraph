REQUIRE BSV

( The spender chooses a fee, and the lock enforces both endpoints. )
REQUIRE stdlib/u32.fth
pels-fee: 1000 2000 ;
: advance ( u32 -- u32 ) u32-inc ;
