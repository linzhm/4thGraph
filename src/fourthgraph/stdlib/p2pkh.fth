REQUIRE BSV

( Return serialized locking Script for an already sized public-key hash. )
: p2pkh-script ( bytes -- bytes )
    bytes-hex 76a914 swap bytes-cat bytes-hex 88ac bytes-cat ;

: p2pkh-lock ( bytes -- bytes ) 20 bytes-check-size p2pkh-script ;
