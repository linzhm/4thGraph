REQUIRE BSV

( Deferred activation commits to a canonical v0.2.0 R1 successor. )

: deferred-is-forkid-single ( bytes -- bytes )
    op-dup bytes-hex 43 s-push op-equal op-swap bytes-hex c3 s-push op-equal op-boolor ;

: deferred-read-activation-preimage ( bytes -- bytes )
    owner-hash s-push target-script-hash s-push op-2drop op-depth op-dup op-1 op-3 op-within
    op-verify op-2 op-numequal op-dup op-toaltstack op-if op-size 161 s-num op-numequalverify
    op-dup 104 s-num op-split op-nip 5 s-num op-split op-swap bytes-hex 04ad68abac s-push
    op-equalverify op-else op-size 158 s-num op-numequalverify op-dup 104 s-num op-split op-nip
    2 s-num op-split op-swap bytes-hex 01ac s-push op-equalverify op-endif ;

: deferred-check-successor ( bytes -- bytes )
    op-8 op-split op-swap
    output-value s-push op-equalverify op-4 op-split op-nip 32 s-num op-split op-drop op-dup
    op-0 32 s-num op-num2bin op-equal op-not op-verify target-output-hash s-push op-equalverify ;

: deferred-check-sighash ( bytes -- bytes )
    op-dup op-size op-4 op-sub op-split op-nip op-1 op-split bytes-hex 000000 s-push
    op-equalverify op-dup deferred-is-forkid-single op-verify op-fromaltstack op-dup
    op-toaltstack op-if 2 s-num op-pick op-1 op-split op-drop bytes-hex 80 s-push op-and op-over
    bytes-hex 80 s-push op-and op-equalverify op-endif op-toaltstack ;

: deferred-bind-activation ( bytes -- bytes )
    op-hash256
    uint256be bytes-cat k1-bind-digest bytes-cat op-fromaltstack op-dup op-toaltstack op-if
    op-rot op-size 33 s-num op-numequalverify op-1 op-split op-swap op-dup
    bytes-hex 000000 s-push op-cat check-type bytes-cat op-dup deferred-is-forkid-single op-not
    op-verify op-toaltstack uint256be bytes-cat k1-bind-digest bytes-cat op-2swap op-endif
    op-fromaltstack op-if op-codeseparator op-checksigverify op-endif op-codeseparator
    op-checksig ;

: deferred-lock ( bytes -- bytes )
    deferred-read-activation-preimage
    deferred-check-successor
    deferred-check-sighash
    deferred-bind-activation ;
