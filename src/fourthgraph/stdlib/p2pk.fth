REQUIRE BSV

( Return serialized locking Script for an already sized public key. )
: p2pk-script ( bytes -- bytes )
    bytes-hex 21 swap bytes-cat bytes-hex ac bytes-cat ;

: p2pk-lock ( bytes -- bytes ) 33 bytes-check-size p2pk-script ;
