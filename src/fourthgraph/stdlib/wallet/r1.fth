( P2PKH-R1 v0.2.0. Script construction runs at compile time. )
( op-* words emit one Script opcode. The R1 words combine them into a full lock. )
( The runtime data-stack conventions are those of the original v0.2.0 template. )

: r1-le-unsigned ( script -- script )
    bytes-hex 00 bsv-push op-cat op-bin2num
;

: r1-zero32 ( script -- script )
    bytes-hex 0000000000000000000000000000000000000000000000000000000000000000 bsv-push
;

: r1-p-type ( script -- script )
    2 bsv-num op-pick op-size op-4 op-sub op-split op-nip
;

: r1-companion-authorization ( script -- script )
    2 bsv-num op-pick op-size 163 bsv-num op-numequalverify op-drop
    2 bsv-num op-pick 104 bsv-num op-split op-nip 7 bsv-num op-split op-drop
    bytes-hex 0663ad67ab68ac bsv-push op-equalverify
    2 bsv-num op-pick 123 bsv-num op-split op-nip 32 bsv-num op-split op-drop r1-zero32
    op-equalverify
    r1-p-type bytes-hex 43000000 bsv-push op-equal op-if bytes-hex 63000000 bsv-push
    op-else r1-p-type bytes-hex c3000000 bsv-push op-equalverify bytes-hex e3000000 bsv-push
    op-endif
;

: r1-select-authorization ( script -- script )
    op-if
    r1-companion-authorization
    op-else
    r1-p-type op-1 op-split op-drop bytes-hex 20 bsv-push op-and bytes-hex 20 bsv-push op-equal
    op-notif
    2 bsv-num op-pick op-size 159 bsv-num op-numequalverify op-drop
    2 bsv-num op-pick 104 bsv-num op-split op-nip 3 bsv-num op-split op-drop
    bytes-hex 0268ac bsv-push op-equalverify
    op-endif
    r1-p-type
    op-endif
;

: r1-check-type ( script -- script )
    bytes-hex 5fffffff bsv-push op-and r1-le-unsigned 65 bsv-num 68 bsv-num op-within op-verify
;

: r1-reverse-byte ( script -- script )
    op-1 op-split op-swap op-toaltstack
;

: r1-append-byte ( script -- script )
    op-fromaltstack op-cat
;

: r1-reverse32 ( script -- script )
    bsv-empty r1-reverse-byte 31 bsv-repeat-code bsv-cat-code
    bsv-empty r1-append-byte 31 bsv-repeat-code bsv-cat-code
;

: r1-uint256be ( script -- script )
    r1-reverse32 bytes-hex 00 bsv-push op-cat op-bin2num
;

: r1-unpack-r1-inputs ( script -- script )
    op-swap 1 bsv-num op-split op-swap op-4 op-equalverify
    32 bsv-num op-split r1-uint256be op-toaltstack r1-uint256be op-toaltstack
    32 bsv-num op-split r1-uint256be op-toaltstack r1-uint256be op-toaltstack
;

: r1-field ( script -- script )
    bytes-hex ffffffff00000001000000000000000000000000ffffffffffffffffffffffff bsv-num-be
;

: r1-n ( script -- script )
    bytes-hex ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 bsv-num-be
;

: r1-f ( script -- script )
    op-depth op-1sub op-pick op-mod
;

: r1-m ( script -- script )
    op-mul r1-f
;

: r1-b ( script -- script )
    bytes-hex 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b bsv-num-be
;

: r1-pos ( script -- script )
    op-depth op-1sub op-pick op-tuck op-mod op-over op-add op-swap op-mod
;

: r1-check-r1-fields ( script -- script )
    r1-field
    op-fromaltstack op-fromaltstack op-fromaltstack op-fromaltstack op-fromaltstack
    ( p r s x y z. Validate both scalars and the explicit finite public point. )
    4 bsv-num op-pick op-1 r1-n op-within op-verify 3 bsv-num op-pick op-1 r1-n op-within
    op-verify
    2 bsv-num op-pick op-0 r1-field op-within op-verify 1 bsv-num op-pick op-0 r1-field
    op-within op-verify
    op-over op-dup r1-m 3 bsv-num op-pick op-dup op-dup r1-m 3 bsv-num op-sub r1-m r1-b op-add
    r1-pos op-numequalverify
;

: r1-b3 ( script -- script )
    bytes-hex 1052a18afeafbbb61bc3380063c994352f57141164fb12e2b36ab4ba777720e2 bsv-num-be
;

: r1-gx ( script -- script )
    bytes-hex 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 bsv-num-be
;

: r1-gy ( script -- script )
    bytes-hex 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 bsv-num-be
;

: r1-gx2 ( script -- script )
    bytes-hex 7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978 bsv-num-be
;

: r1-gy2 ( script -- script )
    bytes-hex 07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1 bsv-num-be
;

: r1-gx3 ( script -- script )
    bytes-hex 5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c bsv-num-be
;

: r1-gy3 ( script -- script )
    bytes-hex 8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032 bsv-num-be
;

: r1-gx4 ( script -- script )
    bytes-hex e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852 bsv-num-be
;

: r1-gy4 ( script -- script )
    bytes-hex e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6 bsv-num-be
;

: r1-gx5 ( script -- script )
    bytes-hex 51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed bsv-num-be
;

: r1-gy5 ( script -- script )
    bytes-hex e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4 bsv-num-be
;

: r1-gx6 ( script -- script )
    bytes-hex b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9 bsv-num-be
;

: r1-gy6 ( script -- script )
    bytes-hex e85c10743237dad56fec0e2dfba703791c00f7701c7e16bdfd7c48538fc77fe2 bsv-num-be
;

: r1-gx7 ( script -- script )
    bytes-hex 8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3 bsv-num-be
;

: r1-gy7 ( script -- script )
    bytes-hex 73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4 bsv-num-be
;

: r1-gx8 ( script -- script )
    bytes-hex 62d9779dbee9b0534042742d3ab54cadc1d238980fce97dbb4dd9dc1db6fb393 bsv-num-be
;

: r1-gy8 ( script -- script )
    bytes-hex ad5accbd91e9d8244ff15d771167cee0a2ed51f6bbe76a78da540a6a0f09957e bsv-num-be
;

: r1-gx9 ( script -- script )
    bytes-hex ea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee0 bsv-num-be
;

: r1-gy9 ( script -- script )
    bytes-hex 2a2744c972c9fce787014a964a8ea0c84d714feaa4de823fe85a224a4dd048fa bsv-num-be
;

: r1-gx10 ( script -- script )
    bytes-hex cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f bsv-num-be
;

: r1-gy10 ( script -- script )
    bytes-hex 878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773 bsv-num-be
;

: r1-gx11 ( script -- script )
    bytes-hex 3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1 bsv-num-be
;

: r1-gy11 ( script -- script )
    bytes-hex 9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740 bsv-num-be
;

: r1-gx12 ( script -- script )
    bytes-hex 741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c4 bsv-num-be
;

: r1-gy12 ( script -- script )
    bytes-hex 0770b46a9c385fdc567383554887b1548eeb912c35ba5ca71995ff22cd4481d3 bsv-num-be
;

: r1-gx13 ( script -- script )
    bytes-hex 177c837ae0ac495a61805df2d85ee2fc792e284b65ead58a98e15d9d46072c01 bsv-num-be
;

: r1-gy13 ( script -- script )
    bytes-hex 63bb58cd4ebea558a24091adb40f4e7226ee14c3a1fb4df39c43bbe2efc7bfd8 bsv-num-be
;

: r1-gx14 ( script -- script )
    bytes-hex 54e77a001c3862b97a76647f4336df3cf126acbe7a069c5e5709277324d2920b bsv-num-be
;

: r1-gy14 ( script -- script )
    bytes-hex f599f1bb29f4317542121f8c05a2e7c37171ea77735090081ba7c82f60d0b375 bsv-num-be
;

: r1-gx15 ( script -- script )
    bytes-hex f0454dc6971abae7adfb378999888265ae03af92de3a0ef163668c63e59b9d5f bsv-num-be
;

: r1-gy15 ( script -- script )
    bytes-hex b5b93ee3592e2d1f4e6594e51f9643e62a3b21ce75b5fa3f47e59cde0d034f36 bsv-num-be
;

: r1-double-point ( script -- script )
    ( Infinity preserves the input point. The branch consumes only this copy. )
    op-dup bsv-optimize? if op-if else op-0notequal op-if then
    ( Use y and z twice to compute s = 2*y*z and leave the input point in place. )
    bsv-optimize? if op-2dup else op-over op-over then op-mul op-dup op-add
    op-dup op-over op-mul op-over op-mul op-depth op-1sub op-pick op-mod
    op-over op-4 op-roll op-mul op-4 op-pick op-over op-mul op-dup op-add op-3 op-6 op-pick op-6
    op-pick op-sub op-7 op-roll op-7 op-roll op-add op-mul op-mul op-dup op-over op-mul op-2
    op-pick op-dup op-add op-sub op-rot op-over op-sub op-rot op-mul op-2 op-pick op-3 op-roll
    op-mul op-dup op-add op-sub op-depth op-1sub op-pick op-mod
    op-swap op-3 op-roll op-mul op-depth op-1sub op-pick op-mod
    op-swap op-rot
    op-endif
;

: r1-add-points ( script -- script )
    ( Cached p and 3b are at the bottom of the stack. The top six items are the input points. )
    op-over op-5 op-pick op-mul op-over op-5 op-pick op-mul -3 bsv-num op-over op-mul op-8
    op-pick op-6 op-pick op-mul op-over op-over op-3 op-mul op-add op-9 op-pick op-9 op-pick
    op-add op-7 op-pick op-7 op-pick op-add op-mul op-5 op-pick op-sub op-4 op-pick op-sub op-11
    op-pick op-11 op-roll op-add op-9 op-pick op-9 op-roll op-add op-mul op-3 op-pick op-sub
    op-6 op-pick op-sub op-10 op-roll op-10 op-roll op-add op-9 op-roll op-9 op-roll op-add
    op-mul op-4 op-pick op-sub op-6 op-pick op-sub -3 bsv-num op-over op-mul op-depth op-2
    op-sub op-pick op-8 op-roll op-mul op-add op-7 op-pick op-over op-add op-8 op-roll op-rot
    op-sub op-rot op-depth op-2 op-sub op-pick op-mul op-3 op-7 op-roll op-8 op-roll op-sub
    op-mul op-sub op-over op-4 op-pick op-mul op-over op-6 op-pick op-mul op-sub op-depth
    op-1sub op-pick op-mod
    op-rot op-3 op-pick op-mul op-rot op-6 op-pick op-mul op-add op-depth op-1sub op-pick op-mod
    op-rot op-4 op-roll op-mul op-3 op-roll op-4 op-roll op-mul op-add op-depth op-1sub op-pick
    op-mod
;

: r1-digits-split4 ( script -- script )
    ( u digit [G]; pop after the Q digit )
    op-over 16 bsv-num op-mod op-toaltstack
    ( v digit [Q] )
    op-dup 16 bsv-num op-mod op-toaltstack
    16 bsv-num op-div op-swap 16 bsv-num op-div op-swap
;

: r1-add-selected ( script -- script )
    op-swap op-sub
    op-dup op-toaltstack op-pick op-fromaltstack
    op-dup op-toaltstack op-pick op-fromaltstack op-pick r1-add-points
;

: r1-step-split4 ( script -- script )
    bsv-empty r1-double-point 4 bsv-repeat-code bsv-cat-code
    ( near table: Q )
    op-fromaltstack 3 bsv-num op-mul 50 bsv-num r1-add-selected
    ( far table: G )
    op-fromaltstack 3 bsv-num op-mul 98 bsv-num r1-add-selected
;

: r1-window ( script -- script )
    op-0 op-1 op-0 r1-gx r1-gy op-1
    r1-gx2 r1-gy2 op-1 r1-gx3 r1-gy3 op-1 r1-gx4 r1-gy4 op-1 r1-gx5 r1-gy5 op-1
    r1-gx6 r1-gy6 op-1 r1-gx7 r1-gy7 op-1 r1-gx8 r1-gy8 op-1 r1-gx9 r1-gy9 op-1
    r1-gx10 r1-gy10 op-1 r1-gx11 r1-gy11 op-1 r1-gx12 r1-gy12 op-1 r1-gx13 r1-gy13 op-1
    r1-gx14 r1-gy14 op-1 r1-gx15 r1-gy15 op-1
    op-0 op-1 op-0 op-fromaltstack op-fromaltstack op-1
    ( 2Q )
    op-3dup r1-double-point
    ( 3Q )
    op-3dup 8 bsv-num op-pick 8 bsv-num op-pick 8 bsv-num op-pick r1-add-points
    ( 4Q )
    5 bsv-num op-pick 5 bsv-num op-pick 5 bsv-num op-pick r1-double-point
    ( 5Q )
    op-3dup 14 bsv-num op-pick 14 bsv-num op-pick 14 bsv-num op-pick r1-add-points
    ( 6Q )
    8 bsv-num op-pick 8 bsv-num op-pick 8 bsv-num op-pick r1-double-point
    ( 7Q )
    op-3dup 20 bsv-num op-pick 20 bsv-num op-pick 20 bsv-num op-pick r1-add-points
    ( 8Q )
    11 bsv-num op-pick 11 bsv-num op-pick 11 bsv-num op-pick r1-double-point
    ( 9Q )
    op-3dup 26 bsv-num op-pick 26 bsv-num op-pick 26 bsv-num op-pick r1-add-points
    ( 10Q )
    14 bsv-num op-pick 14 bsv-num op-pick 14 bsv-num op-pick r1-double-point
    ( 11Q )
    op-3dup 32 bsv-num op-pick 32 bsv-num op-pick 32 bsv-num op-pick r1-add-points
    ( 12Q )
    17 bsv-num op-pick 17 bsv-num op-pick 17 bsv-num op-pick r1-double-point
    ( 13Q )
    op-3dup 38 bsv-num op-pick 38 bsv-num op-pick 38 bsv-num op-pick r1-add-points
    ( 14Q )
    20 bsv-num op-pick 20 bsv-num op-pick 20 bsv-num op-pick r1-double-point
    ( 15Q )
    op-3dup 44 bsv-num op-pick 44 bsv-num op-pick 44 bsv-num op-pick r1-add-points
    op-fromaltstack op-fromaltstack op-swap
    bsv-empty r1-digits-split4 64 bsv-repeat-code bsv-cat-code
    op-2drop op-0 op-1 op-0
    bsv-empty r1-step-split4 64 bsv-repeat-code bsv-cat-code
;

: r1-normalize-endpoint ( script -- script )
    ( Normalize X and Z before the ECDSA x-coordinate comparison. )
    op-depth op-1sub op-pick op-tuck op-mod op-over op-add op-swap op-mod op-swap op-toaltstack
    op-swap op-depth op-1sub op-pick op-tuck op-mod op-over op-add op-swap op-mod op-swap
    op-fromaltstack op-swap
;

: r1-copy-r-low ( script -- script )
    100 bsv-num op-pick
;

: r1-copy-r-high ( script -- script )
    99 bsv-num op-pick
;

: r1-drop-two ( script -- script )
    op-2drop
;

: r1-clear-points ( script -- script )
    bsv-empty r1-drop-two 51 bsv-repeat-code bsv-cat-code
;

: r1-verify-r1-point ( script -- script )
    ( p r s x y z invS. Store u=z/s then v=r/s above saved P. )
    op-dup 2 bsv-num op-pick op-mul r1-n op-mod op-toaltstack
    5 bsv-num op-pick op-mul r1-n op-mod op-toaltstack
    op-drop op-rot op-drop op-toaltstack op-toaltstack
    r1-b3 op-swap
    r1-window
    ( Reject infinity; X/Z is r, or r+n if below p. )
    op-dup op-verify
    r1-normalize-endpoint
    op-dup r1-copy-r-low r1-m 3 bsv-num op-pick op-numequal op-toaltstack
    r1-copy-r-high r1-n op-add op-dup r1-field op-lessthan op-toaltstack
    1 bsv-num op-pick r1-m 3 bsv-num op-pick op-numequal op-fromaltstack op-booland
    op-fromaltstack op-boolor op-verify
    r1-clear-points
;

: r1-k1-gx ( script -- script )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be
;

: r1-k1-n ( script -- script )
    bytes-hex fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 bsv-num-be
;

: r1-der-r ( script -- script )
    bytes-hex 022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802 bsv-push
;

: r1-k1-pub ( script -- script )
    bytes-hex 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push
;

: r1-k1-bind-digest ( script -- script )
    r1-k1-gx op-add r1-k1-n op-mod op-dup op-verify
    op-dup r1-k1-n op-swap op-sub op-min
    op-size op-toaltstack 32 bsv-num op-num2bin r1-reverse32
    32 bsv-num op-fromaltstack op-sub op-split op-nip
    op-size op-tuck op-toaltstack op-cat
    r1-der-r op-swap op-cat op-fromaltstack 36 bsv-num op-add
    bytes-hex 30 bsv-push op-swap op-cat op-swap op-cat op-fromaltstack op-cat
    r1-k1-pub
;

: r1-one-der ( script -- script )
    bytes-hex 3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207abe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push
;

: r1-native-binding ( script -- script )
    ( main: companion/normal native sig and pubkey. alt: mode. )
    op-fromaltstack op-dup op-if
    op-toaltstack op-over op-size op-1sub op-split op-nip bytes-hex 20 bsv-push op-or
    r1-one-der op-swap op-cat r1-k1-pub op-fromaltstack
    op-endif
    op-codeseparator op-if op-checksigverify op-else op-codeseparator op-endif op-checksig
;

: r1-finish-r1-binding ( script -- script )
    op-fromaltstack op-fromaltstack op-fromaltstack
    op-swap op-toaltstack op-swap op-toaltstack
    op-dup op-1 r1-n op-within op-verify
    op-dup 5 bsv-num op-pick op-mul r1-n op-mod op-1 op-numequalverify
    r1-verify-r1-point op-fromaltstack r1-k1-bind-digest
    r1-native-binding
;

: r1-lock ( script -- script )
    ( Runtime stack: preimage public-key signature inverse companion-selector. )
    op-dup op-0 op-2 op-within op-verify op-dup op-toaltstack op-swap
    op-size 32 bsv-num op-numequalverify r1-le-unsigned op-toaltstack
    ( main: P Q sig mode. alt: mode inverse. )
    r1-select-authorization
    r1-check-type
    op-depth 3 bsv-num op-numequalverify
    op-over op-size 65 bsv-num op-numequalverify op-drop
    op-size 64 bsv-num op-numequalverify
    op-over op-hash160 bsv-owner bsv-push op-equalverify
    r1-p-type op-1 op-split op-drop op-toaltstack
    2 bsv-num op-pick op-hash256 r1-uint256be op-dup op-toaltstack op-toaltstack
    r1-unpack-r1-inputs op-drop r1-check-r1-fields
    r1-finish-r1-binding
;
