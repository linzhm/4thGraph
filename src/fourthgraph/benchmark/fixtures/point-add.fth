REQUIRE stdlib/secp256k1.fth

: fixed-generator ( -- bytes )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
;

: add-two ( script -- script )
    ( Runtime input is the field, then valid homogeneous points P and Q. )
    op-depth op-1sub op-pick secp256k1-field op-numequalverify
    op-toaltstack op-toaltstack op-toaltstack
    fixed-generator secp256k1-point-add
    op-fromaltstack op-fromaltstack op-fromaltstack
    rhs-from-stack secp256k1-point-add
;
