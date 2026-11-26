REQUIRE BSV

( These words construct Script. The committed verifier rebuilds the ordered key. )
: lamport-bit ( bytes -- bytes )
    32 s-num op-split op-swap op-sha256 op-swap
    32 s-num op-split op-toaltstack
    op-3 op-pick op-2 op-mod op-if op-swap op-endif op-cat op-cat
    op-swap op-2 op-div op-swap op-fromaltstack ;

: lamport-byte ( bytes -- bytes )
    op-1 op-split op-swap bytes-hex 00 s-push op-cat op-bin2num
    op-swap op-toaltstack op-0 op-rot
    s-empty lamport-bit 8 s-repeat bytes-cat
    op-rot op-0 op-equalverify op-fromaltstack op-fromaltstack
    op-3 op-roll op-cat op-toaltstack ;

: lamport-committed-verifier ( bytes -- bytes )
    op-0 op-toaltstack s-empty lamport-byte 32 s-repeat bytes-cat
    op-0 op-equalverify op-0 op-equalverify op-fromaltstack op-sha256
    key-commitment s-push op-equalverify ;

: lamport-authorization ( bytes -- bytes )
    authorization bytes-cat op-size witness-size s-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack ;

: lamport-bind-spend ( bytes -- bytes ) op-fromaltstack binding bytes-cat ;

: lamport-committed-key ( bytes -- bytes )
    lamport-authorization lamport-committed-verifier lamport-bind-spend ;

: lamport-full-key ( bytes -- bytes )
    lamport-authorization full-key-verifier bytes-cat lamport-bind-spend ;
