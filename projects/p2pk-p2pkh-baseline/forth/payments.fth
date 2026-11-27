REQUIRE BSV

( Construct native locking Script from already sized recipient data. )
REQUIRE stdlib/p2pk.fth
REQUIRE stdlib/p2pkh.fth

: p2pk ( bytes -- bytes ) p2pk-script ;
: p2pkh ( bytes -- bytes ) p2pkh-script ;
