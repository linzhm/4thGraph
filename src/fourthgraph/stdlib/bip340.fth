REQUIRE BSV

( BIP340 verifier. Its runtime stack is message px py signature ry. )
REQUIRE stdlib/script-fragments.fth
REQUIRE stdlib/secp256k1.fth

: bip340-repeat-mask-code ( script cell -- script )
    ( Each emitted DUP CAT doubles the number of copies of the seed. )
    bsv-empty op-dup op-cat swap script-append-repeated
;

: bip340-repeat-mask ( bytes cell -- script )
    bsv-empty rot bsv-push swap bip340-repeat-mask-code
;

: bip340-block-mask ( cell cell -- script )
    ( Build alternating zero and FF blocks. Arguments are block width and doublings. )
    bsv-empty op-0 rot bsv-num op-num2bin op-dup op-invert op-cat swap bip340-repeat-mask-code
;

: bip340-swap-bit-groups ( script cell script -- script )
    ( A mask selects the lower bits of each pair of groups. XOR the differences into both groups. )
    swap rot op-dup over bsv-num op-rshift op-over op-xor
    rot bsv-cat-code op-and op-tuck op-xor op-swap swap bsv-num op-lshift op-xor
;

: bip340-six-field-mask ( script -- script )
    ( Extend a 32-byte mask to all six fields. )
    op-dup op-cat op-dup op-dup op-cat op-cat
;

: bip340-reverse-challenge-fields ( script -- script )
    ( Reverse the bytes within each 32-byte field while preserving field order. )
    8 bytes-hex 00ff 4 bip340-repeat-mask bip340-six-field-mask bip340-swap-bit-groups
    16 bytes-hex 0000ffff 3 bip340-repeat-mask bip340-six-field-mask bip340-swap-bit-groups
    32 4 2 bip340-block-mask bip340-six-field-mask bip340-swap-bit-groups
    64 8 1 bip340-block-mask bip340-six-field-mask bip340-swap-bit-groups
    128 16 0 bip340-block-mask bip340-six-field-mask bip340-swap-bit-groups
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

    ( Check s < n and use the same n for k = n - hash mod n. )
    32 bsv-num op-split op-swap script-le-unsigned secp256k1-order op-2dup op-lessthan op-verify
    op-rot script-le-unsigned op-over op-mod op-sub
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
    swap 2 bip340-copy-point over 3 + bip340-copy-affine secp256k1-add-affine
    2 bip340-copy-point over 6 + bip340-copy-affine secp256k1-add-affine
    2 bip340-copy-point swap 9 + bip340-copy-affine secp256k1-add-affine
;

: bip340-fixed-window-table ( script -- script )
    ( H = 2^128*G. Affine entries are iH+jG, indexed by 4*i+j for indices 1..15. )
    ( Push in descending index order so lookup depth increases with the index. )
    ( 3H + 3G )
    bytes-hex 22f196effb7457a126d4ba1737d777b4ccb27ef9c5f71bc070662075e6fdb2a5 bsv-num-be
    bytes-hex 698ae27abfd7e8022f475b9de5f656154d62c7b03709a9ffeb906106a64ea398 bsv-num-be
    ( 3H + 2G )
    bytes-hex 542a9e2c19b3cf8142d488691ce254c712bb38cc3ef541d87148da7f12a35efc bsv-num-be
    bytes-hex 3c0836ac490413be3b801372e3f8c933ddb79683b5e734484cf6063b6a7570bc bsv-num-be
    ( 3H + 1G )
    bytes-hex cd8a35d25c3fb20209d4ec50084d510321d330a428875fbf9e768da89f7145f9 bsv-num-be
    bytes-hex 27d7773283d0cef6c3878a53167e6665cd74a9ffc0dc2d68df8d3084831d6a36 bsv-num-be
    ( 3H + 0G )
    bytes-hex 38381dbe2e509f228ba93363f2451f08fd845cb351d954be18e2b8edd23809fa bsv-num-be
    bytes-hex e4a32d0a0fb917dcb09405a5520eb1cc3681fccb32d8f24dbd707518331fed52 bsv-num-be
    ( 2H + 3G )
    bytes-hex 96bacf8f2b441e5fdc49d808b8dc940ac57141efeb781e0ecad616853f8cd25a bsv-num-be
    bytes-hex 66f36fc677b9f4e10b9ceca3c17d7d81a968ca68382562d31eab7991be7de2c3 bsv-num-be
    ( 2H + 2G )
    bytes-hex aca2e3e005a5d3391dede3942da3a5eeeb21e55d2ea3603514fe6d77e6d70daa bsv-num-be
    bytes-hex 0484fd61c94008dea9dbafe7db6689f97edc7184ae19fc3466ed28c4df600f39 bsv-num-be
    ( 2H + 1G )
    bytes-hex 2c0e4587cd0123c6505c7ce5bd2623d6ea8b0fa8270f23bf042f7989ce279a45 bsv-num-be
    bytes-hex a02f612707d42762f45baa5c946801ebc881dbf3c5348ebeaa5491ed79858da8 bsv-num-be
    ( 2H + 0G )
    bytes-hex 4d49aefd784e8158fcafebe77fd9af59d89858ade7627eaee6847df84cf27076 bsv-num-be
    bytes-hex cd32fc59a10dd135e723f210359ca6f06e0f2d1a7df4d8466b90b66203aa781e bsv-num-be
    ( 1H + 3G )
    bytes-hex d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0 bsv-num-be
    bytes-hex 4733802b0021932f71d0e9fb7d183b9bf8ad81dabf702624d9c332a8ce3b1f59 bsv-num-be
    ( 1H + 2G )
    bytes-hex d8cc055daffd5f37e6b42b7e9efe1edb7829273eb01b3379c3ee61f64cdbddf5 bsv-num-be
    bytes-hex 1b6888517b304a07b392b1b73e355c3f7ca79ac797de7eaffe116e1069c1cf2e bsv-num-be
    ( 1H + 1G )
    bytes-hex 8b300e513eff872cdaa6d12df54a3e332f27ce937be77e3e63c5e885114cbf09 bsv-num-be
    bytes-hex 1cec30677f43c0cc446f0d466b8238ea08f6a7aa9aaf716926c6ff28b3b10a39 bsv-num-be
    ( 1H + 0G )
    bytes-hex 8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da bsv-num-be
    bytes-hex 662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82 bsv-num-be
    ( 0H + 3G )
    bytes-hex f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9 bsv-num-be
    bytes-hex 388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672 bsv-num-be
    ( 0H + 2G )
    bytes-hex c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 bsv-num-be
    bytes-hex 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a bsv-num-be
    ( 0H + 1G )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be
    bytes-hex 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 bsv-num-be
;

: bip340-check-half ( script -- script )
    op-abs op-dup bip340-half-radix op-lessthan op-verify
;

: bip340-variable-bases ( script -- script )
    ( px py s k -> signed P and Q. Save magnitudes k2 and k1, then s and beta, on the altstack. )
    secp256k1-lambda-split ( px py s k1 k2 )
    3 script-pick-depth 2 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    5 script-pick-depth op-swap op-1 ( signed P )
    ( Retain beta between P and Q until the scalar magnitudes have been saved. )
    7 script-pick-depth secp256k1-beta op-tuck op-mul secp256k1-reduce
    8 script-pick-depth 6 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    op-1 ( signed Q )
    8 script-pick-depth bip340-check-half 8 script-pick-depth bip340-check-half
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
    op-3dup secp256k1-double 2 bip340-copy-point 8 bip340-copy-affine secp256k1-add-affine
    ( P, 2P, 3P. Restore Q to start its row. )
    3 script-restore-items 11 bip340-window-row
    ( The signed endomorphism maps 2P and 3P to the next row starts. )
    17 bip340-copy-point bip340-map-variable-point 23 bip340-window-row
    26 bip340-copy-point bip340-map-variable-point 35 bip340-window-row
    op-fromaltstack op-fromaltstack op-2drop
;

: bip340-uint128le ( script -- script )
    ( The magnitude is below 2^128. Drop the separate positive sign byte. )
    17 bsv-num op-num2bin op-16 op-split op-drop
;

: bip340-pack-windows ( script -- script )
    ( s0 s1 abs-k1 abs-k2 -> 64 bytes with one fixed and one variable index per window. )
    bip340-uint128le bsv-empty op-swap bip340-uint128le op-cat 3 script-append-repeated
    ( Digit positions are numbered from the low end of the 512-bit string. )
    ( Transpose lane and digit bits. The first four swaps also reverse little-endian byte order. )
    ( Swap position bits 4 and 6, complementing both. )
    160 bsv-empty op-0 20 bsv-num op-num2bin bytes-hex ffffffff00000000ffffffff bsv-push op-cat
    1 bip340-repeat-mask-code bip340-swap-bit-groups
    ( Swap position bits 5 and 7, complementing both. )
    320 bsv-empty op-0 40 bsv-num op-num2bin
    op-0 op-8 op-num2bin op-dup op-invert op-tuck op-cat op-cat op-cat bip340-swap-bit-groups
    ( Swap position bits 2 and 4, complementing both. )
    40 bytes-hex 0000000000ff00ff 3 bip340-repeat-mask bip340-swap-bit-groups
    ( Swap position bits 3 and 5, complementing both. )
    80 bsv-empty op-0 op-10 op-num2bin bytes-hex ffff0000ffff bsv-push op-cat
    2 bip340-repeat-mask-code bip340-swap-bit-groups
    ( Swap position bits 0 and 2. )
    6 bytes-hex 00cc 5 bip340-repeat-mask bip340-swap-bit-groups
    ( Swap position bits 1 and 3. )
    12 bytes-hex 0000f0f0 4 bip340-repeat-mask bip340-swap-bit-groups
;

: bip340-nonzero-window-digits ( script -- script )
    ( Leave the input and a ScriptNum whose bytes are 1 where the input digit was nonzero. )
    ( The two shifts and ORs move any of the four bits into bit zero of its byte. )
    op-dup op-dup op-2 op-rshift op-or op-dup op-1 op-rshift op-or
    bytes-hex 01 7 bip340-repeat-mask bsv-cat-code op-and op-bin2num
;

: bip340-spread-window-blocks ( script cell cell -- script )
    ( Move the upper half of each live block into the reserved zeros. )
    ( Build arguments: block width in bytes and mask repetition doublings. )
    over rot rot bip340-block-mask rot op-dup rot
    8 * bsv-num op-lshift op-or swap bsv-cat-code op-and
;

: bip340-expand-window-digits ( script -- script )
    ( Insert a zero byte before each packed nibble pair. )
    op-0 64 bsv-num op-num2bin op-swap op-cat
    32 1 bip340-spread-window-blocks 16 2 bip340-spread-window-blocks
    8 3 bip340-spread-window-blocks 4 4 bip340-spread-window-blocks
    2 5 bip340-spread-window-blocks 1 6 bip340-spread-window-blocks
    ( Move the high nibble into that byte. Return variable, fixed pairs. )
    op-dup op-4 op-lshift op-or bytes-hex 0f 7 bip340-repeat-mask bsv-cat-code op-and
;

: bip340-window-depths ( script -- script )
    bip340-expand-window-digits bip340-nonzero-window-digits op-swap op-bin2num
    ( For digit i and presence m, first compute the variable correction 79*m-5*i. )
    op-2dup op-5 op-mul op-swap 79 bsv-num op-mul op-swap op-sub 128 bsv-num op-num2bin
    bytes-hex ff00 6 bip340-repeat-mask bsv-cat-code op-and op-bin2num
    ( Add the common depth 3*m+2*i. The byte lanes neither carry nor borrow. )
    op-swap op-2 op-mul op-add op-swap op-3 op-mul op-add 128 bsv-num op-num2bin
;

: bip340-joint-window-table ( script -- script )
    ( field r ry px py s k -> r ry TV1..TV15 TF15..TF1 field X Y Z. Save depth pairs on the altstack. )
    bip340-variable-bases bip340-variable-window-table bip340-fixed-window-table
    op-fromaltstack bip340-half-radix op-2dup op-div op-toaltstack op-mod
    3 script-restore-items bip340-pack-windows bip340-window-depths op-toaltstack
    ( Keep the field prime immediately below the accumulator for all window arithmetic. )
    op-depth op-1sub op-roll op-0 op-1 op-0
;

: bip340-variable-window-add ( script -- script )
    ( The input is zero or the lookup depth with the index and accumulator in place. )
    op-ifdup op-if
      ( Keep the depth on the main stack while copying X and Y. )
      op-dup op-pick op-over op-pick op-rot op-1sub op-pick 1 secp256k1-add-with-field
    op-endif
;

: bip340-fixed-window-add ( script -- script )
    ( The input is zero or the depth of the affine x coordinate. )
    op-ifdup op-if
      op-dup op-toaltstack op-pick op-fromaltstack op-pick 1 secp256k1-add-affine-with-field
    op-endif
;

: bip340-window-addends ( script -- script )
    ( Read the pair in one split, then split just those two bytes. )
    ( A nonzero depth is a minimal positive ScriptNum, and a zero byte skips addition. )
    op-fromaltstack op-2 op-split op-toaltstack op-1 op-split op-toaltstack
    bip340-variable-window-add
    op-fromaltstack bip340-fixed-window-add
;

: bip340-joint-window-step ( script -- script )
    ( Accumulator = 4*accumulator + one point from each table. )
    1 secp256k1-double-pair-with-field bip340-window-addends
;

: bip340-joint-multiply ( script -- script )
    bip340-joint-window-table
    ( The initial accumulator is infinity. Drop the empty stream after the last window. )
    bip340-window-addends bsv-empty bip340-joint-window-step 63 script-append-repeated
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
