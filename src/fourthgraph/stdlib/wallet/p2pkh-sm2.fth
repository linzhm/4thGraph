REQUIRE BSV

( SM2 spending condition. The wallet supplies the precompiled ZA and SM3 fragments. )

: sm2-p-type ( script -- script )
    2 bsv-num op-pick op-size op-4 op-sub op-split op-nip ;

: sm2-zero32 ( script -- script )
    bytes-hex 0000000000000000000000000000000000000000000000000000000000000000 bsv-push ;

: sm2-check-owner ( script -- script )
    op-over op-size 65 bsv-num op-numequalverify op-drop op-size 64 bsv-num op-numequalverify
    op-over op-hash160 owner-hash bsv-push op-equalverify ;

: sm2-reverse-byte ( script -- script )
    op-1 op-split op-swap op-toaltstack ;

: sm2-append-byte ( script -- script )
    op-fromaltstack op-cat ;

: sm2-reverse32 ( script -- script )
    bsv-empty sm2-reverse-byte 31 bsv-repeat-code bsv-cat-code bsv-empty sm2-append-byte 31 bsv-repeat-code bsv-cat-code ;

: sm2-uint256be ( script -- script )
    sm2-reverse32 bytes-hex 00 bsv-push op-cat op-bin2num ;

: sm2-unpack-sm2-inputs ( script -- script )
    op-swap 1 bsv-num op-split op-swap op-4 op-equalverify 32 bsv-num op-split sm2-uint256be
    op-toaltstack sm2-uint256be op-toaltstack 32 bsv-num op-split sm2-uint256be op-toaltstack
    sm2-uint256be op-toaltstack ;

: sm2-field ( script -- script )
    bytes-hex fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff bsv-num-be ;

: sm2-n ( script -- script )
    bytes-hex fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123 bsv-num-be ;

: sm2-f ( script -- script )
    op-depth op-1sub op-pick op-mod ;

: sm2-m ( script -- script )
    op-mul sm2-f ;

: sm2-b ( script -- script )
    bytes-hex 28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93 bsv-num-be ;

: sm2-pos ( script -- script )
    op-depth op-1sub op-pick op-tuck op-mod op-over op-add op-swap op-mod ;

( The point formulas use bounded residues in Fp. Template 3 also permits negative residues. )
: sm2-reduce-coordinate ( script -- script )
    signed-residues? if sm2-f else sm2-pos then ;

: sm2-check-sm2-fields ( script -- script )
    sm2-field op-fromaltstack op-fromaltstack op-fromaltstack op-fromaltstack op-fromaltstack
    4 bsv-num op-pick op-1 sm2-n op-within op-verify 3 bsv-num op-pick op-1 sm2-n op-within
    op-verify 2 bsv-num op-pick op-0 sm2-field op-within op-verify 1 bsv-num op-pick op-0 sm2-field
    op-within op-verify op-over op-dup sm2-m 3 bsv-num op-pick op-dup op-dup sm2-m 3 bsv-num op-sub
    sm2-m sm2-b op-add sm2-pos op-numequalverify ;

: sm2-b3 ( script -- script )
    bytes-hex 7abdefdbd8de1a9ce80fdae36e2f1cf7dac69ddf4102aeb8993637c3e8bc2bb9 bsv-num-be ;

: sm2-gx ( script -- script )
    bytes-hex 32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7 bsv-num-be ;

: sm2-gy ( script -- script )
    bytes-hex bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0 bsv-num-be ;

: sm2-gx2 ( script -- script )
    bytes-hex 56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52 bsv-num-be ;

: sm2-gy2 ( script -- script )
    bytes-hex 31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3 bsv-num-be ;

: sm2-gx3 ( script -- script )
    bytes-hex a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf bsv-num-be ;

: sm2-gy3 ( script -- script )
    bytes-hex 530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6 bsv-num-be ;

: sm2-gx4 ( script -- script )
    bytes-hex c239507105c683242a81052ff641ed69009a084ad5cc937db21646cd34a0ced5 bsv-num-be ;

: sm2-gy4 ( script -- script )
    bytes-hex b1bf7ec4080f3c8735f1294ac0db19686bee2e96ab8c71fb7a253666cb66e009 bsv-num-be ;

: sm2-gx5 ( script -- script )
    bytes-hex c749061668652e26040e008fdd5eb77a344a417b7fce19dba575da57cc372a9e bsv-num-be ;

: sm2-gy5 ( script -- script )
    bytes-hex f2df5db2d144e9454504c622b51cf38f5006206eb579ff7da6976eff5fbe6480 bsv-num-be ;

: sm2-gx6 ( script -- script )
    bytes-hex 0927afb57d93483bbb17c93e71f22a3105ff8856a66016892c8b1a1a3c4b0d30 bsv-num-be ;

: sm2-gy6 ( script -- script )
    bytes-hex 150c6b1ab4d1fc7eac1c0ef6ebf2664581adf1f0855a064dd572103000088f63 bsv-num-be ;

: sm2-gx7 ( script -- script )
    bytes-hex ddf092555409c19dfdbe86a75c139906a80198337744ee78cd27e384d9fcaf15 bsv-num-be ;

: sm2-gy7 ( script -- script )
    bytes-hex 847d18ffb38e87065cd6b6e9c12d2922037937707d6a49a2223b949657e52bc1 bsv-num-be ;

: sm2-gx8 ( script -- script )
    bytes-hex b9c3faeb4b1610713db4333d4e860e64d4ea35d60c1c29bb675d822ded0bb916 bsv-num-be ;

: sm2-gy8 ( script -- script )
    bytes-hex c519b309ecf7269c2491d2de9accf2be0366a8a03024b3e03c286da2cfd31a3e bsv-num-be ;

: sm2-gx9 ( script -- script )
    bytes-hex a27233f3a59595080b4a2444a46a74c5fe8d59cb43619e4f173472a58cca247e bsv-num-be ;

: sm2-gy9 ( script -- script )
    bytes-hex 379e72f63722c924768f7689b210f45fc3a8433140d1ebca85227940922c02e9 bsv-num-be ;

: sm2-gx10 ( script -- script )
    bytes-hex d3f94862519621c121666061f65c3e32b2d0d065cd219e3284a04814db522756 bsv-num-be ;

: sm2-gy10 ( script -- script )
    bytes-hex 4b9030cf676f6a742ebd57d146dca428f6b743f64d1482d147d46fb2bab82a14 bsv-num-be ;

: sm2-gx11 ( script -- script )
    bytes-hex 04b3cb10c9c6d8e27c1aab770f67f543125dcdd589c2ff82668c74d78ce20ace bsv-num-be ;

: sm2-gy11 ( script -- script )
    bytes-hex 63516355287e39fe4918e5c02e2b0b930c94816e63c4bc72739a8fd805174a4b bsv-num-be ;

: sm2-gx12 ( script -- script )
    bytes-hex bfc2df6bb17f971ad89058ca059be46e5f7b516c5bdaddad9c9f042d0279270a bsv-num-be ;

: sm2-gy12 ( script -- script )
    bytes-hex b145513f59636106cef696b67939bd7b73c9fc6fd150aaaab5fbf87b64af3c26 bsv-num-be ;

: sm2-gx13 ( script -- script )
    bytes-hex 952072d6ff9c65bdfa804513275f58aa7bea65c6421e189e2b834f1d509b9cd0 bsv-num-be ;

: sm2-gy13 ( script -- script )
    bytes-hex e6bb9804458bb70f1a473f8d9748f23858d1434ae934ba7503891e105e009b00 bsv-num-be ;

: sm2-gx14 ( script -- script )
    bytes-hex 83b4a4de96a4d70f4aaf81826982d748ef22ea28be9d44de0a44248a36bb0a07 bsv-num-be ;

: sm2-gy14 ( script -- script )
    bytes-hex e481c0d9ee8a98d4eeb6d6c6d7e74f8e3e707c8a438529492e663cd4373a2f24 bsv-num-be ;

: sm2-gx15 ( script -- script )
    bytes-hex f73b839f13912c1a3291676c38d393243b424f35f0ecce4c461b1bbcb80f829c bsv-num-be ;

: sm2-gy15 ( script -- script )
    bytes-hex 32ec7722695dc7cf5ee9fab985c12455dc2e788fb170aa144c3533771db0955e bsv-num-be ;

: sm2-drop-two ( script -- script )
    op-2drop ;

: sm2-double-point-unrolled ( script -- script )
    op-dup op-0notequal op-if 2 bsv-num op-pick op-over op-sub 3 bsv-num op-pick 2 bsv-num op-pick
    op-add op-mul 3 bsv-num op-mul 2 bsv-num op-pick 2 bsv-num op-pick op-mul op-dup op-add 3 bsv-num
    op-pick op-over op-mul 5 bsv-num op-pick op-over op-mul op-dup op-add 3 bsv-num op-pick op-dup
    op-mul op-over op-dup op-add op-sub op-dup 4 bsv-num op-pick op-mul sm2-reduce-coordinate 2 bsv-num op-pick
    2 bsv-num op-pick op-sub 6 bsv-num op-pick op-mul 4 bsv-num op-pick op-dup op-mul op-dup op-add
    op-sub sm2-reduce-coordinate 5 bsv-num op-pick op-dup op-mul 6 bsv-num op-pick op-mul sm2-reduce-coordinate op-toaltstack
    op-toaltstack op-toaltstack bsv-empty sm2-drop-two 4 bsv-repeat-code bsv-cat-code op-fromaltstack
    op-fromaltstack op-fromaltstack op-endif ;

: sm2-cached-b3 ( script -- script )
    op-depth op-2 op-sub op-pick ;

: sm2-add-points-unrolled ( script -- script )
    5 bsv-num op-pick 3 bsv-num op-pick op-mul 5 bsv-num op-pick 3 bsv-num op-pick op-mul 5 bsv-num
    op-pick 3 bsv-num op-pick op-mul 8 bsv-num op-pick 8 bsv-num op-pick op-add 6 bsv-num op-pick
    6 bsv-num op-pick op-add op-mul 3 bsv-num op-pick op-sub 2 bsv-num op-pick op-sub 9 bsv-num op-pick
    8 bsv-num op-pick op-add 7 bsv-num op-pick 6 bsv-num op-pick op-add op-mul 4 bsv-num op-pick op-sub
    2 bsv-num op-pick op-sub 9 bsv-num op-pick 9 bsv-num op-pick op-add 7 bsv-num op-pick 7 bsv-num
    op-pick op-add op-mul 4 bsv-num op-pick op-sub 3 bsv-num op-pick op-sub 1 bsv-num op-pick 3 bsv-num
    op-mul op-negate 4 bsv-num op-pick sm2-cached-b3 op-mul op-add 5 bsv-num op-pick 1 bsv-num op-pick
    op-sub 6 bsv-num op-pick 2 bsv-num op-pick op-add 6 bsv-num op-pick 3 bsv-num op-mul op-negate
    9 bsv-num op-pick 3 bsv-num op-mul 1 bsv-num op-pick op-add 6 bsv-num op-pick sm2-cached-b3 op-mul
    11 bsv-num op-pick 3 bsv-num op-pick op-sub 3 bsv-num op-mul op-sub 8 bsv-num op-pick 5 bsv-num
    op-pick op-mul 7 bsv-num op-pick 2 bsv-num op-pick op-mul op-sub sm2-reduce-coordinate 5 bsv-num op-pick 5 bsv-num
    op-pick op-mul 3 bsv-num op-pick 3 bsv-num op-pick op-mul op-add sm2-reduce-coordinate 8 bsv-num op-pick 6 bsv-num
    op-pick op-mul 11 bsv-num op-pick 5 bsv-num op-pick op-mul op-add sm2-reduce-coordinate op-toaltstack
    op-toaltstack op-toaltstack bsv-empty sm2-drop-two 9 bsv-repeat-code bsv-cat-code op-fromaltstack
    op-fromaltstack op-fromaltstack ;

: sm2-double-point ( script -- script )
    compiled-points? if sm2-double-kernel bsv-cat-code else sm2-double-point-unrolled then ;

: sm2-add-points ( script -- script )
    compiled-points? if sm2-add-kernel bsv-cat-code else sm2-add-points-unrolled then ;

: sm2-digits-split4 ( script -- script )
    op-over 16 bsv-num op-mod op-toaltstack op-dup 16 bsv-num op-mod op-toaltstack 16 bsv-num op-div
    op-swap 16 bsv-num op-div op-swap ;

: sm2-add-selected ( script -- script )
    op-swap op-sub op-dup op-toaltstack op-pick op-fromaltstack op-dup op-toaltstack op-pick
    op-fromaltstack op-pick sm2-add-points ;

: sm2-step-split4 ( script -- script )
    bsv-empty sm2-double-point 4 bsv-repeat-code bsv-cat-code op-fromaltstack 3 bsv-num op-mul 50 bsv-num
    sm2-add-selected op-fromaltstack 3 bsv-num op-mul 98 bsv-num sm2-add-selected ;

: sm2-window ( script -- script )
    op-0 op-1 op-0 sm2-gx sm2-gy op-1 sm2-gx2 sm2-gy2 op-1 sm2-gx3 sm2-gy3 op-1 sm2-gx4 sm2-gy4
    op-1 sm2-gx5 sm2-gy5 op-1 sm2-gx6 sm2-gy6 op-1 sm2-gx7 sm2-gy7 op-1 sm2-gx8 sm2-gy8 op-1
    sm2-gx9 sm2-gy9 op-1 sm2-gx10 sm2-gy10 op-1 sm2-gx11 sm2-gy11 op-1 sm2-gx12 sm2-gy12 op-1
    sm2-gx13 sm2-gy13 op-1 sm2-gx14 sm2-gy14 op-1 sm2-gx15 sm2-gy15 op-1 op-0 op-1 op-0
    op-fromaltstack op-fromaltstack op-1 op-3dup sm2-double-point op-3dup 8 bsv-num op-pick
    8 bsv-num op-pick 8 bsv-num op-pick sm2-add-points 5 bsv-num op-pick 5 bsv-num op-pick 5 bsv-num
    op-pick sm2-double-point op-3dup 14 bsv-num op-pick 14 bsv-num op-pick 14 bsv-num op-pick
    sm2-add-points 8 bsv-num op-pick 8 bsv-num op-pick 8 bsv-num op-pick sm2-double-point op-3dup
    20 bsv-num op-pick 20 bsv-num op-pick 20 bsv-num op-pick sm2-add-points 11 bsv-num op-pick 11 bsv-num
    op-pick 11 bsv-num op-pick sm2-double-point op-3dup 26 bsv-num op-pick 26 bsv-num op-pick 26 bsv-num
    op-pick sm2-add-points 14 bsv-num op-pick 14 bsv-num op-pick 14 bsv-num op-pick sm2-double-point
    op-3dup 32 bsv-num op-pick 32 bsv-num op-pick 32 bsv-num op-pick sm2-add-points 17 bsv-num op-pick
    17 bsv-num op-pick 17 bsv-num op-pick sm2-double-point op-3dup 38 bsv-num op-pick 38 bsv-num op-pick
    38 bsv-num op-pick sm2-add-points 20 bsv-num op-pick 20 bsv-num op-pick 20 bsv-num op-pick
    sm2-double-point op-3dup 44 bsv-num op-pick 44 bsv-num op-pick 44 bsv-num op-pick sm2-add-points
    op-fromaltstack op-fromaltstack op-swap bsv-empty sm2-digits-split4 64 bsv-repeat-code bsv-cat-code
    op-2drop op-0 op-1 op-0 bsv-empty sm2-step-split4 64 bsv-repeat-code bsv-cat-code ;

: sm2-copy-r-low ( script -- script )
    100 bsv-num op-pick ;

: sm2-copy-r-high ( script -- script )
    99 bsv-num op-pick ;

: sm2-clear-points ( script -- script )
    bsv-empty sm2-drop-two 51 bsv-repeat-code bsv-cat-code ;

( Canonicalize X and Z before comparing X to a nonnegative multiple of Z modulo p. )
: sm2-normalize-result ( script -- script )
    signed-residues? if op-rot sm2-pos op-rot op-rot sm2-pos then ;

: sm2-verify-sm2-point ( script -- script )
    3 bsv-num op-pick op-toaltstack 4 bsv-num op-pick 4 bsv-num op-pick op-add sm2-n op-mod op-dup
    op-verify op-toaltstack op-negate 4 bsv-num op-pick op-add sm2-n op-mod sm2-n op-add sm2-n
    op-mod op-toaltstack 2 bsv-num op-roll op-drop 2 bsv-num op-roll op-drop op-fromaltstack op-swap
    op-toaltstack op-swap op-toaltstack sm2-b3 op-swap sm2-window op-dup op-verify sm2-normalize-result op-dup
    sm2-copy-r-low sm2-m 3 bsv-num op-pick op-numequal op-toaltstack sm2-copy-r-high sm2-n op-add
    op-dup sm2-field op-lessthan op-toaltstack 1 bsv-num op-pick sm2-m 3 bsv-num op-pick op-numequal
    op-fromaltstack op-booland op-fromaltstack op-boolor op-verify sm2-clear-points ;

: sm2-k1-gx ( script -- script )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be ;

: sm2-k1-n ( script -- script )
    bytes-hex fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 bsv-num-be ;

: sm2-der-r ( script -- script )
    bytes-hex 022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802 bsv-push ;

: sm2-k1-pub ( script -- script )
    bytes-hex 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push ;

: sm2-k1-bind-digest ( script -- script )
    sm2-k1-gx op-add sm2-k1-n op-mod op-dup op-verify op-dup sm2-k1-n op-swap op-sub op-min
    op-size op-toaltstack 32 bsv-num op-num2bin sm2-reverse32 32 bsv-num op-fromaltstack op-sub
    op-split op-nip op-size op-tuck op-toaltstack op-cat sm2-der-r op-swap op-cat
    op-fromaltstack 36 bsv-num op-add bytes-hex 30 bsv-push op-swap op-cat op-swap op-cat
    op-fromaltstack op-cat sm2-k1-pub ;

: sm2-verify-owner-signature ( script -- script )
    2 bsv-num op-pick op-hash256 op-dup sm2-uint256be op-toaltstack 2 bsv-num op-pick op-1 op-split
    op-nip za-tail bsv-cat-code op-swap op-cat sm3-za bsv-cat-code op-swap op-cat
    sm3-message bsv-cat-code sm2-uint256be op-toaltstack sm2-unpack-sm2-inputs op-drop
    sm2-check-sm2-fields sm2-verify-sm2-point op-fromaltstack sm2-k1-bind-digest ;

: sm2-one-der ( script -- script )
    bytes-hex 3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207abe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push ;

: sm2-check-witness-format ( script -- script )
    op-depth 3 bsv-num op-numequalverify sm2-p-type op-dup bytes-hex 5fffffff bsv-push op-and
    bytes-hex 00 bsv-push op-cat op-bin2num 65 bsv-num 68 bsv-num op-within op-verify op-dup
    bytes-hex 43000000 bsv-push op-equal op-swap bytes-hex c3000000 bsv-push op-equal op-boolor
    3 bsv-num op-pick op-size 161 bsv-num op-numequal op-nip op-booland op-dup op-toaltstack op-if
    2 bsv-num op-pick 104 bsv-num op-split op-nip 5 bsv-num op-split op-drop
    bytes-hex 04ad68abac bsv-push op-equalverify 2 bsv-num op-pick 121 bsv-num op-split op-nip
    32 bsv-num op-split op-drop sm2-zero32 op-equalverify op-else sm2-p-type op-1 op-split op-drop
    bytes-hex 20 bsv-push op-and bytes-hex 00 bsv-push op-equal op-if 2 bsv-num op-pick op-size
    158 bsv-num op-numequalverify op-drop 2 bsv-num op-pick 104 bsv-num op-split op-nip 2 bsv-num
    op-split op-drop bytes-hex 01ac bsv-push op-equalverify op-endif op-endif ;

: sm2-bind-spend ( script -- script )
    op-fromaltstack
    op-if op-over op-size op-1sub op-split op-nip bytes-hex 20 bsv-push op-or sm2-one-der op-swap
    op-cat sm2-k1-pub op-2swap op-codeseparator op-checksigverify op-endif op-codeseparator
    op-checksig ;

: sm2-lock ( script -- script )
    sm2-check-witness-format
    sm2-check-owner
    sm2-p-type op-1 op-split op-drop op-toaltstack
    sm2-verify-owner-signature
    sm2-bind-spend ;
