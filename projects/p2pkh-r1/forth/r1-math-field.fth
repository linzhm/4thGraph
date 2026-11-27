REQUIRE BSV

( P-256 domain constants and ordinary modular inversion. )
range: r1-coordinate script-int 0
    $ffffffff00000001000000000000000000000000ffffffffffffffffffffffff ;
range: r1-field-prime script-int
    $ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    $ffffffff00000001000000000000000000000001000000000000000000000000 ;
range: r1-curve-constant script-int
    $5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    $5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604c ;

: r1-prime ( script -- script )
    bytes-hex ffffffff00000001000000000000000000000000ffffffffffffffffffffffff bsv-num-be
;

: r1-order ( script -- script )
    bytes-hex ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 bsv-num-be
;

: r1-constant-b ( script -- script )
    bytes-hex 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b bsv-num-be
;

: r1-generator ( script -- script )
    bytes-hex 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 bsv-num-be
    bytes-hex 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 bsv-num-be
    op-1
;

: r1-reduce-positive ( script -- script )
    ( Runtime: a modulus -- residue. )
    op-tuck op-mod op-over op-add op-swap op-mod
;

: r1-euclid-step ( script -- script )
    ( Runtime state: old-remainder remainder old-coefficient coefficient. )
    ( If the remainder is nonzero, replace both pairs using the quotient. )
    op-2 op-pick op-0notequal op-if
        op-3 op-pick op-3 op-pick op-div
        op-over op-mul op-2 op-pick op-swap op-sub op-toaltstack
        op-swap op-drop op-toaltstack
        op-tuck op-mod
        op-fromaltstack op-fromaltstack
    op-endif
;

: r1-inverse ( script -- script )
    ( Runtime: modulus a -- inverse. Requires 0 < a < modulus < 2^256. )
    ( Lamé bound: 384 Euclidean divisions suffice for 256-bit inputs. )
    op-over op-toaltstack op-0 op-1
    bsv-empty r1-euclid-step 256 bsv-repeat-code bsv-cat-code
    bsv-empty r1-euclid-step 128 bsv-repeat-code bsv-cat-code
    op-drop op-toaltstack
    op-0 op-numequalverify op-1 op-numequalverify
    op-fromaltstack op-fromaltstack r1-reduce-positive
;
