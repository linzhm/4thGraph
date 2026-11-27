REQUIRE BSV

( The witness stack contains the preimage, signature, and companion selector. )
: ml-dsa-payment-lock ( bytes bytes bytes -- cell )
    check-authorization
    swap OP_HASH256 dup rot
    reconstruct-challenge OP_EQUALVERIFY
    bind-input ;
