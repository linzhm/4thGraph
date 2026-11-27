REQUIRE BSV
REQUIRE counter.fth

( The terminal transition receives state first, then the external delta. )
range: delta-range u32 1 5 ;
: decide-with-delta ( u32 u32 -- route )
    check-range delta-range u32+ decide ;
