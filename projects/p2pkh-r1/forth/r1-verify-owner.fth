REQUIRE r1-math-verify.fth
REQUIRE stdlib/script-fragments.fth

: r1-check-owner-witness ( script bytes -- script )
    ( Runtime: public-key signature digest -- unchanged. )
    swap
    op-depth op-3 op-numequalverify
    op-size 32 bsv-num op-numequalverify
    op-over op-size 64 bsv-num op-numequalverify op-drop
    op-2 op-pick op-size 65 bsv-num op-numequalverify
    op-hash160 swap bsv-push op-equalverify
;

: r1-decode-owner-witness ( script -- script )
    ( Runtime: public-key signature digest -- x y r s e. )
    script-uint256be op-toaltstack
    32 bsv-num op-split script-uint256be op-toaltstack script-uint256be op-toaltstack
    op-1 op-split op-swap bytes-hex 04 bsv-push op-equalverify
    32 bsv-num op-split script-uint256be op-toaltstack script-uint256be
    op-fromaltstack op-fromaltstack op-fromaltstack op-fromaltstack
;

: r1-verify-owner ( script bytes -- script )
    ( The R1 signature uses the digest that PELS has authenticated. )
    r1-check-owner-witness r1-decode-owner-witness r1-verify
;
