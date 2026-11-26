REQUIRE BSV

( BIP340 verifier. Its runtime stack is message px py signature ry. )
REQUIRE stdlib/script-fragments.fth
REQUIRE stdlib/secp256k1.fth

: bip340-challenge-tag ( script -- script )
    ( SHA256 of BIP0340/challenge, repeated twice. )
    bytes-hex 7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c dup bytes-cat bsv-push
;

: bip340-half-radix ( script -- script )
    bytes-hex 0100000000000000000000000000000000 bsv-num-be
;
: bip340-check-size ( script cell -- script ) swap op-size swap bsv-num op-numequalverify op-drop ;
: bip340-copy-challenge-field ( script -- script ) op-fromaltstack op-dup op-toaltstack ;
: bip340-check-field-coordinate ( script -- script )
    script-uint256be 0 script-pick-depth bip340-copy-challenge-field op-lessthan op-verify
;
: bip340-check-even ( script cell -- script ) script-pick-depth op-2 op-mod op-0 op-numequalverify ;

: bip340-prepare-challenge ( script -- script )
    ( Input: message pxBytes pyBytes signature ryBytes. )
    secp256k1-field op-toaltstack
    3 script-pick-depth 32 bip340-check-size 2 script-pick-depth 32 bip340-check-size
    1 script-pick-depth 64 bip340-check-size 0 script-pick-depth 32 bip340-check-size
    1 script-pick-depth 32 bsv-num op-split ( rBytes sBytes )
    5 script-pick-depth bip340-check-field-coordinate ( px )
    5 script-pick-depth bip340-check-field-coordinate ( py )
    3 script-pick-depth bip340-check-field-coordinate ( r )
    5 script-pick-depth bip340-check-field-coordinate ( ry )
    4 script-pick-depth script-uint256be 0 script-pick-depth secp256k1-order op-lessthan op-verify ( s )
    3 bip340-check-even 1 bip340-check-even ( py and ry are even. )
    ( Check that P is on the curve. The endpoint comparison will check R. )
    3 script-pick-depth 4 script-pick-depth op-mul ( py^2 )
    5 script-pick-depth 6 script-pick-depth op-mul 0 script-pick-depth 7 script-pick-depth op-mul ( px^3 )
    0 script-pick-depth op-7 op-add 3 script-pick-depth 1 script-pick-depth op-sub
    0 script-pick-depth bip340-copy-challenge-field op-mod op-0 op-numequalverify
    ( e = SHA256 of tag || rBytes || pxBytes || message, reduced mod n. )
    bip340-challenge-tag 0 script-pick-depth 13 script-pick-depth op-cat
    0 script-pick-depth 18 script-pick-depth op-cat 0 script-pick-depth 20 script-pick-depth op-cat
    op-sha256 script-uint256be 0 script-pick-depth secp256k1-order op-dup op-toaltstack op-mod
    op-fromaltstack 1 script-pick-depth op-sub op-fromaltstack ( k = n-e. Restore the field prime. )
    1 script-save-depth 12 script-save-depth 15 script-save-depth 16 script-save-depth 13 script-save-depth 14 script-save-depth 0 script-save-depth
    12 script-drop-pairs 7 script-restore-items ( field r ry px py s k )
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
    ( px py s k -> signed P and Q. Save the magnitudes of k2 and k1, then s, on the altstack. )
    secp256k1-lambda-split ( px py s k1 k2 )
    3 script-pick-depth 2 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    5 script-pick-depth op-swap op-1 ( signed P )
    7 script-pick-depth secp256k1-endomorphism-x
    7 script-pick-depth 5 script-pick-depth op-0 op-lessthan op-if op-negate op-endif
    op-1 ( signed Q )
    7 script-pick-depth bip340-check-half 7 script-pick-depth bip340-check-half
    op-toaltstack op-toaltstack 8 script-pick-depth op-toaltstack
    bsv-empty op-toaltstack 6 bsv-repeat-code bsv-cat-code
    op-2drop op-2drop op-drop 6 script-restore-items
;

: bip340-variable-window-table ( script -- script )
    ( Input: three coordinates each of signed P and Q. )
    op-toaltstack op-toaltstack op-toaltstack
    op-3dup secp256k1-double 2 bip340-copy-point 8 bip340-copy-affine secp256k1-add-affine
    ( P, 2P, 3P. Restore Q to start its row. )
    3 script-restore-items 11 bip340-window-row
    11 bip340-copy-point secp256k1-double 23 bip340-window-row
    23 bip340-copy-point 14 bip340-copy-point secp256k1-add 35 bip340-window-row
;

: bip340-uint128le ( script -- script )
    ( The magnitude is below 2^128. Drop the separate positive sign byte. )
    17 bsv-num op-num2bin op-16 op-split op-drop
;

: bip340-swap-window-digits ( script cell bytes -- script )
    ( A mask selects the lower position of each digit pair. XOR the differences into both positions. )
    swap rot op-dup over bsv-num op-rshift op-over op-xor
    rot bsv-push op-and op-tuck op-xor op-swap swap bsv-num op-lshift op-xor
;

: bip340-pack-windows ( script -- script )
    ( s0 s1 abs-k1 abs-k2 -> 64 bytes with one fixed and one variable index per window. )
    bip340-uint128le bsv-empty op-swap bip340-uint128le op-cat 3 script-append-repeated
    ( Digit positions are numbered from the low end of the 512-bit string. )
    ( Transpose lane and digit bits. The first four swaps also reverse little-endian byte order. )
    ( Swap position bits 4 and 6, complementing both. )
    160 bytes-hex 0000000000000000000000000000000000000000ffffffff00000000ffffffff0000000000000000000000000000000000000000ffffffff00000000ffffffff bip340-swap-window-digits
    ( Swap position bits 5 and 7, complementing both. )
    320 bytes-hex 00000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff0000000000000000ffffffffffffffff bip340-swap-window-digits
    ( Swap position bits 2 and 4, complementing both. )
    40 bytes-hex 0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff bip340-swap-window-digits
    ( Swap position bits 3 and 5, complementing both. )
    80 bytes-hex 00000000000000000000ffff0000ffff00000000000000000000ffff0000ffff00000000000000000000ffff0000ffff00000000000000000000ffff0000ffff bip340-swap-window-digits
    ( Swap position bits 0 and 2. )
    6 bytes-hex 00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc00cc bip340-swap-window-digits
    ( Swap position bits 1 and 3. )
    12 bytes-hex 0000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f00000f0f0 bip340-swap-window-digits
;

: bip340-joint-window-table ( script -- script )
    ( field r ry px py s k -> r ry TV1..TV15 TF15..TF1 field X Y Z. Save window bytes on the altstack. )
    bip340-variable-bases bip340-variable-window-table bip340-fixed-window-table
    op-fromaltstack bip340-half-radix op-2dup op-div op-toaltstack op-mod
    3 script-restore-items bip340-pack-windows op-toaltstack
    ( Keep the field prime immediately below the accumulator for all window arithmetic. )
    op-depth op-1sub op-roll op-0 op-1 op-0
;

: bip340-variable-window-add ( script -- script )
    ( Variable points occupy three stack items. For TV15, X is at depth 36. )
    op-ifdup op-if op-3 op-mul 82 bsv-num op-swap op-sub
      ( Keep the depth on the main stack while copying X and Y. )
      op-dup op-pick op-over op-pick op-rot op-1sub op-pick 1 secp256k1-add-with-field
    op-endif
;

: bip340-fixed-window-add ( script -- script )
    ( Fixed points are affine and occupy two items. For TF1, x is at depth 5. )
    op-ifdup op-if op-2 op-mul op-3 op-add
      op-dup op-toaltstack op-pick op-fromaltstack op-pick 1 secp256k1-add-affine-with-field
    op-endif
;

: bip340-window-addends ( script -- script )
    ( Read one byte from the stream. The low nibble indexes the fixed table. )
    op-fromaltstack op-1 op-split op-toaltstack
    op-dup op-15 op-and op-bin2num op-toaltstack
    op-4 op-rshift op-bin2num bip340-variable-window-add
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
