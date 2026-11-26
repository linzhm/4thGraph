REQUIRE BSV

( The input is a BIP143 or OTDA preimage, signature, and companion selector. )
: ml-dsa-payment-verifier ( bytes -- bytes )
    op-over op-size 32 s-num op-numequalverify op-drop
    decode-signature bytes-cat
    op-toaltstack op-over sample-challenge bytes-cat
    op-swap op-cat check-equation bytes-cat
    op-fromaltstack apply-hints bytes-cat
    op-toaltstack op-toaltstack message-prefix s-push op-swap op-cat hash-message bytes-cat
    op-fromaltstack op-swap op-fromaltstack op-cat hash-challenge bytes-cat op-equal ;

: ml-dsa-check-authorization ( bytes -- bytes )
    authorization bytes-cat op-swap op-hash256 op-dup op-toaltstack op-swap ;

: ml-dsa-lock ( bytes -- bytes )
    ml-dsa-check-authorization
    ml-dsa-payment-verifier op-verify op-fromaltstack binding bytes-cat ;
