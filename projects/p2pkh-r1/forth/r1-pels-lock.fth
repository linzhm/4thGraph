REQUIRE stdlib/wallet/pels-verify.fth
REQUIRE r1-verify-owner.fth

: increment-and-pay-fee ( script -- script )
    ( Runtime: current-state previous-amount -- successor-state successor-amount. )
    ( One successor, with a 1,000 sat fee and a wrapping u32 counter. )
    1000 bsv-num op-sub op-dup op-0 op-greaterthan op-verify op-8 op-num2bin
    op-swap op-bin2num op-1add bytes-hex 0100000000 bsv-num-be op-mod op-5 op-num2bin op-swap
;

: r1-pels-body ( script -- script )
    bsv-empty increment-and-pay-fee pels-verify
    bsv-owner r1-verify-owner
;

: r1-pels-state ( script bytes -- script )
    bsv-push op-codeseparator
;

: r1-pels-lock ( script bytes -- script )
    r1-pels-state r1-pels-body
;
