REQUIRE BSV

( One outer lock supports the canonical, cached-constants, and cached-steps verifiers. )
: wots-check-authorization ( bytes -- bytes )
    authorization bytes-cat op-size 2144 s-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack ;

: wots-plus-lock ( bytes -- bytes )
    wots-check-authorization
    wots-verifier bytes-cat op-fromaltstack binding bytes-cat ;
