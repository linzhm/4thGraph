REQUIRE BSV
bytes-param: owner-key 33 ;

: check-signature ( bytes bytes -- cell )
    OP_CHECKSIG ;

lock: p2pk ( signature:bytes )
    signature owner-key check-signature verify ;
