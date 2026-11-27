REQUIRE stdlib/script-fragments.fth

( Native authentication of the candidate message in nChain LS1. )
( The fixed public key and nonce convention are for transaction binding. )

: pels-binding-scalar ( script -- script )
    script-uint256be
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be op-add
    bytes-hex fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 bsv-num-be
    op-tuck op-mod op-dup op-verify op-tuck op-sub op-min
;

: pels-binding-der ( script -- script )
    pels-binding-scalar op-size op-toaltstack
    32 bsv-num op-num2bin script-reverse32
    32 bsv-num op-fromaltstack op-sub op-split op-nip
    op-size op-tuck op-toaltstack op-cat
    bytes-hex 022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802 bsv-push
    op-swap op-cat op-fromaltstack 36 bsv-num op-add
    bytes-hex 30 bsv-push op-swap op-cat op-swap op-cat
;

: pels-bind-digest ( script -- script )
    ( Runtime: digest -- the same digest, after CHECKSIGVERIFY against this input. )
    op-dup pels-binding-der
    bytes-hex 41 bsv-push op-cat
    bytes-hex 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-push
    op-checksigverify
;
