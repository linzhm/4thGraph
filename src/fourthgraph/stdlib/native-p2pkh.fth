REQUIRE BSV
bytes-param: owner-hash 20 ;

: check-owner ( bytes -- cell )
    OP_HASH160 owner-hash OP_EQUAL ;

: check-signature ( bytes bytes -- cell )
    OP_CHECKSIG ;

lock: p2pkh ( signature:bytes public-key:bytes )
    signature public-key dup
    check-owner verify
    check-signature verify ;
