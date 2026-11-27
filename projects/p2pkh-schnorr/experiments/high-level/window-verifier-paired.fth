REQUIRE BSV
REQUIRE batch-witness.fth

layout: pair-model-input ( rx:script-int ry:script-int px:script-int py:script-int s:script-int
                           k:script-int p:script-int -- s k p rx ry px py )
layout: pair-model-result ( s:script-int k:script-int p:script-int rx:script-int ry:script-int
                            px:script-int py:script-int -- rx ry px py s k p )

lock: window-bip340-paired ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-batch
    field-prime pair-model-input map-affine-pair pair-model-result
    secp256k1-joint-mapped-point check-nonce
    1
;
