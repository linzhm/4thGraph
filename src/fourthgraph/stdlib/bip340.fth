REQUIRE BSV

( BIP340 verifier. Its runtime stack is message px py signature ry. )
REQUIRE stdlib/script-fragments.fth
REQUIRE stdlib/secp256k1.fth
REQUIRE stdlib/secp256k1-window.fth

: bip340-six-field-mask ( script -- script )
    ( Extend a 32-byte mask to all six fields. )
    op-dup op-cat op-dup op-dup op-cat op-cat
;

: bip340-reverse-challenge-fields ( script -- script )
    ( Reverse the bytes within each 32-byte field while preserving field order. )
    8 bytes-hex 00ff 4 script-repeat-mask bip340-six-field-mask script-swap-bit-groups
    16 bytes-hex 0000ffff 3 script-repeat-mask bip340-six-field-mask script-swap-bit-groups
    32 4 2 script-block-mask bip340-six-field-mask script-swap-bit-groups
    64 8 1 script-block-mask bip340-six-field-mask script-swap-bit-groups
    128 16 0 script-block-mask bip340-six-field-mask script-swap-bit-groups
;

: bip340-challenge-tag ( script -- script )
    ( SHA256 of BIP0340/challenge, repeated twice. )
    bytes-hex 7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c bsv-push op-dup op-cat
;

: bip340-half-radix ( script -- script )
    bytes-hex 0100000000000000000000000000000000 bsv-num-be
;
: bip340-check-size ( script cell -- script ) swap op-size swap bsv-num op-numequalverify ;
: bip340-check-field-coordinate ( script -- script )
    op-dup op-depth op-1sub op-pick op-lessthan op-verify
;
: bip340-check-even ( script cell -- script ) script-pick-depth op-2 op-mod op-0 op-numequalverify ;

: bip340-prepare-challenge ( script -- script )
    ( Input: message pxBytes pyBytes signature ryBytes. )
    3 script-pick-depth 32 bip340-check-size op-drop 2 script-pick-depth 32 bip340-check-size op-drop
    1 script-pick-depth 64 bip340-check-size op-drop 32 bip340-check-size
    op-swap 32 bsv-num op-split ( message pxBytes pyBytes ryBytes rBytes sBytes )

    ( Hash the original big-endian encodings, consuming the message. )
    bip340-challenge-tag 2 script-pick-depth op-cat 5 script-pick-depth op-cat
    op-6 op-roll op-cat op-sha256
    ( Join px, py, r, ry, s and the hash, then reverse each field. )
    op-cat op-rot op-swap op-cat op-cat op-cat op-cat bip340-reverse-challenge-fields
    secp256k1-field op-swap
    bsv-empty 32 bsv-num op-split op-swap script-le-unsigned bip340-check-field-coordinate op-swap
    4 script-append-repeated ( px py r ry scalarBytes )

    3 bip340-check-even 1 bip340-check-even ( py and ry are even. )
    ( Check that P is on the curve. The endpoint comparison will check R. )
    3 script-pick-depth op-dup op-mul
    5 script-pick-depth op-dup op-dup op-mul op-mul op-7 op-add op-sub
    secp256k1-reduce op-0 op-numequalverify

    ( Check s < n, compute k = n - hash mod n, and pass n to the scalar split. )
    32 bsv-num op-split op-swap script-le-unsigned secp256k1-order op-2dup op-lessthan op-verify
    op-rot script-le-unsigned op-over op-mod op-over op-toaltstack op-sub
    op-2rot op-2swap ( field r ry px py s k )
;

: bip340-copy-point ( script cell -- script )
    ( PICK the same depth three times as x, y, z are appended. )
    bsv-empty swap script-pick-depth 3 bsv-repeat-code bsv-cat-code
;

: bip340-copy-affine ( script cell -- script )
    ( Copy x and y at the same depth in succession. )
    bsv-empty swap script-pick-depth 2 bsv-repeat-code bsv-cat-code
;

: bip340-window-row ( script cell -- script )
    ( The build argument is the depth of P.x. The top point is iQ. )
    ( Append iQ+P, iQ+2P and iQ+3P using the original affine P. )
    swap 2 bip340-copy-point over 3 + bip340-copy-affine 0 secp256k1-scaled-add-affine-with-field
    2 bip340-copy-point over 6 + bip340-copy-affine 0 secp256k1-scaled-add-affine-with-field
    2 bip340-copy-point swap 9 + bip340-copy-affine 0 secp256k1-scaled-add-affine-with-field
;

: bip340-fixed-window-table ( script -- script )
    ( H = 2^128*G. Affine entries are the scaled images of iH+jG. )
    ( Push in descending index order so lookup depth increases with the index. )
    ( 3H + 3G )
    bytes-hex c08069beccafc29c6706b7eccd2e704074530db893f98e7e0913952fe327f956 bsv-num-be
    bytes-hex e66f1389d1228ca131e0707e67b094844a942d639cbd6a69e14e42f129204533 bsv-num-be
    ( 3H + 2G )
    bytes-hex 1b09c95c145ac4cafb3411f7b2b83afb1a0e9187602fdcc242b7d039b7353937 bsv-num-be
    bytes-hex d91b9324e364110e7abda266a1cd6be9c9e0acfd15c55ba3631f2a382b8127da bsv-num-be
    ( 3H + 1G )
    bytes-hex 25666b4cfb79b2e3fd2b60586a0e089d6d28aea2d00c51ac5bdcd2f5dfbf69be bsv-num-be
    bytes-hex 698952b11202a36a8597f267e77838dbb07d44ec3797ac38a909fb3a614d7dbb bsv-num-be
    ( 3H + 0G )
    bytes-hex ab76f76bd3bdea038a1ceefd70230f592394a3480cbb77f3dd6ec887c9c32f60 bsv-num-be
    bytes-hex b9c35d18b5230e5501c4de1c0e5d481747e9e16daa4dce93269e25d423da7899 bsv-num-be
    ( 2H + 3G )
    bytes-hex 2f021825b4a2b617454b76195550211327d534bfa21cc63e613618b2d65f5fd5 bsv-num-be
    bytes-hex cd9ca68aa2b3ae054b888d9dc4cbe473ec8116582df11cc7becbe2f46d643f5c bsv-num-be
    ( 2H + 2G )
    bytes-hex 415e055a974971b95fe98f323f190bdaf2378332e18b7aee41bf9dbfbbb8691a bsv-num-be
    bytes-hex f5ee32d835ea3e128717f135deb5f62cb5332ae31455cac2e59649be8e46889f bsv-num-be
    ( 2H + 1G )
    bytes-hex 0a7002b30eb9a8d74356e594b0a227084640ae6c4052e9b6b940c71c9ec6fb0f bsv-num-be
    bytes-hex 27ce87e2025045aa2382e6afc93b1337bebc1164e38b4c46774d566160a0a4a1 bsv-num-be
    ( 2H + 0G )
    bytes-hex dcc614ca6913f9eaaf78cb2d45e29fdddc3cd8811c88ef04964db664590f2686 bsv-num-be
    bytes-hex 31cfbcd20906dc85436f02d037770817ca5e8982e0900d7915ff4fbdd78c5fd1 bsv-num-be
    ( 1H + 3G )
    bytes-hex fa08163740e55dee891326dfdf30d553d09555497c4d85bb1d7a14444bbb86a0 bsv-num-be
    bytes-hex 81ef831878fdd91a23a31463aa85321947f2527f339b6cb305687ae873a3cf62 bsv-num-be
    ( 1H + 2G )
    bytes-hex f686879fa354ac91f418e19ed6f243f838aba0da749ccdbac2c3acd82c24f761 bsv-num-be
    bytes-hex fbee66c5cae8aac24a2ea18a0ba9f77875b4d1984cfca189053c5c3e331d5756 bsv-num-be
    ( 1H + 1G )
    bytes-hex a70483e0b6c8e92d1c3621df08d515697d4cb95ef32220a7f10f27a713dffcb3 bsv-num-be
    bytes-hex 7f8b470ebba7e4be292d7b5a3268132e6969c7d7623aed98110d81db637488b9 bsv-num-be
    ( 1H + 0G )
    bytes-hex 53627daf9bc9923562d2467ccd24596bf7dc8345317ac0d8a192ff23df70e140 bsv-num-be
    bytes-hex 551c750058e66c83da017e7f8f61dbcd78e92bc9123f1045d68935db616540e4 bsv-num-be
    ( 0H + 3G )
    bytes-hex 11f9f794e1e908f08d1a7292b789cff6809e4e3655a18b95448940f8eaa098bf bsv-num-be
    bytes-hex 594a0da00be1ffee31066c84281127e2b34cad3f2bcd4f1e47021503cc23c4fa bsv-num-be
    ( 0H + 2G )
    bytes-hex 44d6beceecc78aa4a4fa56454f8f222d4de63d42438216b9002f185a7bbf7a98 bsv-num-be
    bytes-hex e424c163bad80762ab0759ab9c4c2d1b8e0ef275ba1e6031809977256cd6ca28 bsv-num-be
    ( 0H + 1G )
    bytes-hex 42d3bd21aea1c1e79058d690970ffc5eede9cebbe465250e53e9965741a42898 bsv-num-be
    bytes-hex ab90aa570a2cf6d7845ec0ca06cc6bd9b9c687e0c37ab3091840a43560b247b3 bsv-num-be
;

: bip340-variable-bases ( script -- script )
    ( px py s k, with n atop the altstack -> signed P and Q. )
    ( Save magnitudes k2 and k1, then s and beta, on the altstack. )
    op-fromaltstack secp256k1-lambda-split-with-order ( px py s k1 k2 )
    3 script-pick-depth 2 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    5 script-pick-depth op-swap op-1 ( signed P )
    ( Retain beta between P and Q until the scalar magnitudes have been saved. )
    7 script-pick-depth secp256k1-beta op-tuck op-mul secp256k1-reduce
    8 script-pick-depth 6 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    op-1 ( signed Q )
    ( The lattice bounds both magnitudes below 2^128 for k in 0..n. )
    8 script-pick-depth op-abs 8 script-pick-depth op-abs
    op-toaltstack op-toaltstack 9 script-pick-depth op-toaltstack
    op-3 op-roll op-toaltstack
    bsv-empty op-toaltstack 6 bsv-repeat-code bsv-cat-code
    op-2drop op-2drop op-drop 6 script-restore-items
;

: bip340-map-variable-point ( script -- script )
    ( Restore and retain the relative sign and beta. Map X to beta*X and Y to sign*Y. )
    op-fromaltstack op-fromaltstack op-2dup op-toaltstack op-toaltstack
    op-4 op-roll op-mul secp256k1-reduce
    op-2swap op-3 op-roll op-rot op-mul op-swap
;

: bip340-variable-window-table ( script -- script )
    ( Input: three coordinates each of signed P and Q, with beta atop the altstack. )
    ( The affine y coordinates agree when the scalar signs agree. Save +1 or -1. )
    4 script-pick-depth 2 script-pick-depth op-numequal op-2 op-mul op-1sub op-toaltstack
    op-toaltstack op-toaltstack op-toaltstack
    op-3dup 0 secp256k1-scaled-double-with-field
    2 bip340-copy-point 8 bip340-copy-affine 0 secp256k1-scaled-add-affine-with-field
    ( P, 2P, 3P. Restore Q to start its row. )
    3 script-restore-items 11 bip340-window-row
    ( The signed endomorphism maps 2P and 3P to the next row starts. )
    17 bip340-copy-point bip340-map-variable-point 23 bip340-window-row
    26 bip340-copy-point bip340-map-variable-point 35 bip340-window-row
    op-fromaltstack op-fromaltstack op-2drop
;

: bip340-pack-windows ( script -- script ) secp-window-pack-windows ;
: bip340-window-depths ( script -- script ) secp-window-window-depths ;

: bip340-joint-window-table ( script -- script )
    ( Consume n from the altstack. Save depth pairs there after constructing the tables. )
    ( field r ry px py s k -> r ry TV1..TV15 TF15..TF1 field X Y Z. )
    op-toaltstack op-toaltstack secp256k1-scale-affine-pair op-fromaltstack op-fromaltstack
    bip340-variable-bases bip340-variable-window-table bip340-fixed-window-table
    op-fromaltstack bip340-half-radix op-2dup op-div op-toaltstack op-mod
    3 script-restore-items secp-window-pack-windows secp-window-window-depths op-toaltstack
    ( Keep the field prime immediately below the accumulator for all window arithmetic. )
    op-depth op-1sub op-roll op-0 op-1 op-0
;

: bip340-variable-window-add ( script -- script )
    ( The input is zero or the lookup depth with the index and accumulator in place. )
    op-ifdup op-if
      secp-window-pick-variable-point 1 secp256k1-scaled-add-with-field
    op-endif
;

: bip340-fixed-window-add ( script -- script )
    ( The input is zero or the depth of the affine x coordinate. )
    op-ifdup op-if
      op-dup op-toaltstack op-pick op-fromaltstack op-pick 1 secp256k1-scaled-add-affine-with-field
    op-endif
;

: bip340-first-window ( script -- script )
    secp-window-read-window
    ( The accumulator is infinity. A nonzero variable selection replaces it. )
    op-ifdup op-if
      secp-window-pick-variable-point op-2rot op-2drop op-3 op-roll op-drop
    op-endif
    op-fromaltstack bip340-fixed-window-add
;

: bip340-window-addends ( script -- script )
    secp-window-read-window
    bip340-variable-window-add
    op-fromaltstack bip340-fixed-window-add
;

: bip340-joint-window-step ( script -- script )
    ( Accumulator = 4*accumulator + one point from each table. )
    1 secp256k1-scaled-double-pair-with-field bip340-window-addends
;

: bip340-joint-multiply ( script -- script )
    bip340-joint-window-table
    ( The initial accumulator is infinity. Drop the empty stream after the last window. )
    bip340-first-window bsv-empty bip340-joint-window-step 63 script-append-repeated
    op-fromaltstack op-drop
    ( Reject infinity. Compare X and Y to r*Z and ry*Z modulo the field prime. )
    op-dup op-verify
    80 script-pick-depth 1 script-pick-depth op-mul 3 script-pick-depth op-swap op-sub
    4 script-pick-depth op-mod op-0 op-numequalverify
    79 script-pick-depth 1 script-pick-depth op-mul 2 script-pick-depth op-swap op-sub
    4 script-pick-depth op-mod op-0 op-numequalverify
    40 script-drop-pairs op-drop op-1
;

: bip340-check-witness-depth ( script -- script ) op-depth op-5 op-numequalverify ;

: bip340-verify ( script -- script )
    bip340-check-witness-depth bip340-prepare-challenge bip340-joint-multiply ;
