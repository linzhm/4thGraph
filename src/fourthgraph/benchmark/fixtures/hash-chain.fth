REQUIRE stdlib/hash-chain.fth

: hash-chain-checkpoint ( script -- script )
    ( The first digest is observable as an output before the next region. )
    1 sha256-chain op-dup op-toaltstack
    65 sha256-chain
    op-fromaltstack op-swap
;
