( Return serialized locking Script for a 20-byte public-key hash. )
: p2pkh-lock ( bytes -- bytes )
    20 bytes-check-size
    bytes-hex 76a914 swap bytes-cat bytes-hex 88ac bytes-cat ;
