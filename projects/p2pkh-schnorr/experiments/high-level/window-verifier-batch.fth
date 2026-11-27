REQUIRE BSV
REQUIRE verifier.fth

: exact-field ( bytes -- bytes ) 32 bytes-check-size ;
layout: raw-fields ( m:bytes px:bytes py:bytes sig:bytes ry:bytes -- m sig ry px py )
layout: extract-signature ( m:bytes sig:bytes ry:bytes py:bytes px:bytes -- m px py ry sig )
layout: hash-witness ( m:bytes px:bytes py:bytes ry:bytes r:bytes s:bytes -- px py r ry s m px r )

: decode-witness ( bytes bytes bytes bytes bytes --
                   script-int script-int script-int script-int script-int script-int )
    exact-field raw-fields exact-field swap exact-field
    extract-signature signature-halves hash-witness challenge-digest
    bytes-cat bytes-cat bytes-cat bytes-cat bytes-cat uint256be-fields
;

: validate-coordinate ( script-int -- script-int ) dup field-prime int< verify ;
: validate-ordinate ( script-int -- script-int )
    validate-coordinate dup 2 cell>int int-rem 0 cell>int int= verify
;

layout: public-y ( px:script-int py:script-int r:script-int ry:script-int s:script-int e:script-int -- px r ry s e py )
layout: public-x ( px:script-int r:script-int ry:script-int s:script-int e:script-int py:script-int -- r ry s e py px )
layout: validate-public ( r:script-int ry:script-int s:script-int e:script-int py:script-int px:script-int p:script-int --
                          r ry s e px py p px py )
layout: nonce-y ( r:script-int ry:script-int s:script-int e:script-int px:script-int py:script-int -- r s e px py ry )
layout: nonce-x ( r:script-int s:script-int e:script-int px:script-int py:script-int ry:script-int -- s e px py ry r )
layout: decoded-scalar ( s:script-int e:script-int px:script-int py:script-int ry:script-int r:script-int -- r ry px py e s )

: prepare-batch ( bytes bytes bytes bytes bytes -- script-int script-int script-int script-int script-int script-int )
    decode-witness public-y validate-ordinate public-x validate-coordinate field-prime validate-public check-curve
    nonce-y validate-ordinate nonce-x validate-coordinate decoded-scalar
    dup group-order int< verify swap group-order int-rem group-order swap int-
;

lock: window-bip340-batch ( message:bytes public-x-bytes:bytes public-y-bytes:bytes signature:bytes nonce-y-bytes:bytes )
    message public-x-bytes public-y-bytes signature nonce-y-bytes prepare-batch
    secp256k1-joint-window-2 check-nonce
    1
;
