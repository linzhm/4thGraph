REQUIRE BSV

( Reconstruct c_tilde. The backend lowers decompression, sampling,
  polynomial arithmetic, hint application and SHAKE256 as separate words. )
: ml-dsa-challenge ( script -- script )
    op-over op-size ml-dsa-message-bytes bsv-num op-numequalverify op-drop
    ml-dsa-decode-signature

    ( message, c_tilde, z, hints -> message, c_tilde, c || z )
    op-toaltstack op-over ml-dsa-sample-challenge
    op-swap op-cat ml-dsa-verify-equation
    op-fromaltstack ml-dsa-apply-hints

    ( Derive mu from the approved message and append the reconstructed w1. )
    op-toaltstack op-toaltstack ml-dsa-mu-prefix bsv-push op-swap op-cat
    ml-dsa-hash-mu
    op-fromaltstack op-swap op-fromaltstack op-cat
    ml-dsa-hash-challenge
;

: ml-dsa-verify-message ( script -- script )
    ml-dsa-challenge op-equal
;
