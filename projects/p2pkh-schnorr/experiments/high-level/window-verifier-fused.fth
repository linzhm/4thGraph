REQUIRE BSV
REQUIRE batch-witness.fth

lock: window-bip340-fused ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-batch
    secp256k1-joint-scaled-point scaled-nonce-residuals require-nonce-residues
    1
;
