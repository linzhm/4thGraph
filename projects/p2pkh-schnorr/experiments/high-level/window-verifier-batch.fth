REQUIRE BSV
REQUIRE batch-witness.fth

lock: window-bip340-batch ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-batch
    secp256k1-joint-window-2 check-nonce
    1
;
