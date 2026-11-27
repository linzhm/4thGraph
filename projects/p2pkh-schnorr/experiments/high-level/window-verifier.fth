REQUIRE BSV
REQUIRE verifier.fth

lock: window-bip340 ( message:bytes public-x:bytes public-y:bytes signature:bytes nonce-y:bytes )
    field-prime public-x field-coordinate public-y even-coordinate check-curve
    signature signature-halves drop field-coordinate
    nonce-y even-coordinate

    public-x field-coordinate public-y even-coordinate
    signature signature-halves nip checked-scalar
    group-order message public-x signature signature-halves drop challenge int-
    secp256k1-joint-window-2 check-nonce
    1
;
