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
: bip340-initial-window-mask ( script -- script )
    ( 4^63 selects the most significant two-bit digit of a 128-bit scalar. )
    bytes-hex 40000000000000000000000000000000 bsv-num-be
;

: bip340-check-size ( script cell -- script ) swap op-size swap bsv-num op-numequalverify op-drop ;
: bip340-check-field-coordinate ( script -- script )
    script-uint256be 0 script-pick-depth secp256k1-field op-lessthan op-verify
;
: bip340-check-even ( script cell -- script ) script-pick-depth op-2 op-mod op-0 op-numequalverify ;

: bip340-prepare-challenge ( script -- script )
    ( Input: message pxBytes pyBytes signature ryBytes. )
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
    0 script-pick-depth secp256k1-field op-mod op-0 op-numequalverify
    ( e = SHA256 of tag || rBytes || pxBytes || message, reduced mod n. )
    bip340-challenge-tag 0 script-pick-depth 13 script-pick-depth op-cat
    0 script-pick-depth 18 script-pick-depth op-cat 0 script-pick-depth 20 script-pick-depth op-cat
    op-sha256 script-uint256be 0 script-pick-depth secp256k1-order op-mod
    secp256k1-order 1 script-pick-depth op-sub secp256k1-field ( k = n-e )
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
    ( 0H + 1G )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be
    bytes-hex 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 bsv-num-be
    ( 0H + 2G )
    bytes-hex c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 bsv-num-be
    bytes-hex 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a bsv-num-be
    ( 0H + 3G )
    bytes-hex f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9 bsv-num-be
    bytes-hex 388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672 bsv-num-be
    ( 1H + 0G )
    bytes-hex 8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da bsv-num-be
    bytes-hex 662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82 bsv-num-be
    ( 1H + 1G )
    bytes-hex 8b300e513eff872cdaa6d12df54a3e332f27ce937be77e3e63c5e885114cbf09 bsv-num-be
    bytes-hex 1cec30677f43c0cc446f0d466b8238ea08f6a7aa9aaf716926c6ff28b3b10a39 bsv-num-be
    ( 1H + 2G )
    bytes-hex d8cc055daffd5f37e6b42b7e9efe1edb7829273eb01b3379c3ee61f64cdbddf5 bsv-num-be
    bytes-hex 1b6888517b304a07b392b1b73e355c3f7ca79ac797de7eaffe116e1069c1cf2e bsv-num-be
    ( 1H + 3G )
    bytes-hex d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0 bsv-num-be
    bytes-hex 4733802b0021932f71d0e9fb7d183b9bf8ad81dabf702624d9c332a8ce3b1f59 bsv-num-be
    ( 2H + 0G )
    bytes-hex 4d49aefd784e8158fcafebe77fd9af59d89858ade7627eaee6847df84cf27076 bsv-num-be
    bytes-hex cd32fc59a10dd135e723f210359ca6f06e0f2d1a7df4d8466b90b66203aa781e bsv-num-be
    ( 2H + 1G )
    bytes-hex 2c0e4587cd0123c6505c7ce5bd2623d6ea8b0fa8270f23bf042f7989ce279a45 bsv-num-be
    bytes-hex a02f612707d42762f45baa5c946801ebc881dbf3c5348ebeaa5491ed79858da8 bsv-num-be
    ( 2H + 2G )
    bytes-hex aca2e3e005a5d3391dede3942da3a5eeeb21e55d2ea3603514fe6d77e6d70daa bsv-num-be
    bytes-hex 0484fd61c94008dea9dbafe7db6689f97edc7184ae19fc3466ed28c4df600f39 bsv-num-be
    ( 2H + 3G )
    bytes-hex 96bacf8f2b441e5fdc49d808b8dc940ac57141efeb781e0ecad616853f8cd25a bsv-num-be
    bytes-hex 66f36fc677b9f4e10b9ceca3c17d7d81a968ca68382562d31eab7991be7de2c3 bsv-num-be
    ( 3H + 0G )
    bytes-hex 38381dbe2e509f228ba93363f2451f08fd845cb351d954be18e2b8edd23809fa bsv-num-be
    bytes-hex e4a32d0a0fb917dcb09405a5520eb1cc3681fccb32d8f24dbd707518331fed52 bsv-num-be
    ( 3H + 1G )
    bytes-hex cd8a35d25c3fb20209d4ec50084d510321d330a428875fbf9e768da89f7145f9 bsv-num-be
    bytes-hex 27d7773283d0cef6c3878a53167e6665cd74a9ffc0dc2d68df8d3084831d6a36 bsv-num-be
    ( 3H + 2G )
    bytes-hex 542a9e2c19b3cf8142d488691ce254c712bb38cc3ef541d87148da7f12a35efc bsv-num-be
    bytes-hex 3c0836ac490413be3b801372e3f8c933ddb79683b5e734484cf6063b6a7570bc bsv-num-be
    ( 3H + 3G )
    bytes-hex 22f196effb7457a126d4ba1737d777b4ccb27ef9c5f71bc070662075e6fdb2a5 bsv-num-be
    bytes-hex 698ae27abfd7e8022f475b9de5f656154d62c7b03709a9ffeb906106a64ea398 bsv-num-be
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

: bip340-joint-window-table ( script -- script )
    ( field r ry px py s k -> field r ry TV1..TV15 TF1..TF15 low high k1 k2 mask X Y Z. )
    bip340-variable-bases bip340-variable-window-table bip340-fixed-window-table
    op-fromaltstack bip340-half-radix op-2dup op-div op-toaltstack op-mod op-fromaltstack
    op-fromaltstack op-fromaltstack bip340-initial-window-mask op-0 op-1 op-0
;

: bip340-window-index ( script cell -- script )
    ( Build argument: depth of the high scalar. Its low scalar is one item deeper. )
    swap over script-pick-depth 4 script-pick-depth op-div op-4 op-mod op-4 op-mul
    swap 2 + script-pick-depth 5 script-pick-depth op-div op-4 op-mod op-add
;

: bip340-variable-window-add ( script -- script )
    ( Variable points occupy three stack items. For TV15, X is at depth 40. )
    op-ifdup op-if op-3 op-mul 86 bsv-num op-swap op-sub
      ( Keep the depth on the main stack while copying X and Y. )
      op-dup op-pick op-over op-pick op-rot op-1sub op-pick secp256k1-add
    op-endif
;

: bip340-fixed-window-add ( script -- script )
    ( Fixed points are affine and occupy two items. For TF15, x is at depth 9. )
    op-ifdup op-if op-2 op-mul 39 bsv-num op-swap op-sub
      op-dup op-toaltstack op-pick op-fromaltstack op-pick secp256k1-add-affine
    op-endif
;

: bip340-window-addends ( script -- script )
    4 bip340-window-index bip340-variable-window-add
    6 bip340-window-index bip340-fixed-window-add
;

: bip340-next-window ( script -- script )
    ( Advance the mask and return it below the accumulator. )
    op-3 op-roll op-4 op-div op-2swap op-3 op-roll
;

: bip340-joint-window-step ( script -- script )
    ( Accumulator = 4*accumulator + one point from each table. )
    secp256k1-double-pair bip340-window-addends bip340-next-window
;

: bip340-joint-multiply ( script -- script )
    bip340-joint-window-table
    ( The initial accumulator is infinity. The final window does not advance the mask. )
    bip340-window-addends bip340-next-window
    bsv-empty bip340-joint-window-step 62 bsv-repeat-code bsv-cat-code
    secp256k1-double-pair bip340-window-addends
    ( Reject infinity. Compare X and Y to r*Z and ry*Z modulo the field prime. )
    op-dup op-verify
    84 script-pick-depth 1 script-pick-depth op-mul 3 script-pick-depth op-swap op-sub
    secp256k1-reduce op-0 op-numequalverify
    83 script-pick-depth 1 script-pick-depth op-mul 2 script-pick-depth op-swap op-sub
    secp256k1-reduce op-0 op-numequalverify
    43 script-drop-pairs op-1
;

: bip340-check-witness-depth ( script -- script ) op-depth op-5 op-numequalverify ;

: bip340-verify ( script -- script )
    bip340-check-witness-depth bip340-prepare-challenge bip340-joint-multiply ;
