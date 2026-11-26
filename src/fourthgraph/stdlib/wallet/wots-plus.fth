( One outer lock supports the canonical, cached-constants, and cached-steps verifiers. )
: wots-plus-lock ( bytes -- bytes )
    authorization bytes-cat op-size 2144 s-num op-numequalverify
    op-swap op-hash256 op-dup op-toaltstack
    wots-verifier bytes-cat op-fromaltstack binding bytes-cat ;
