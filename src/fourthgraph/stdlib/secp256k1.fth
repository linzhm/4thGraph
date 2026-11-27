REQUIRE BSV

( secp256k1 constants and complete homogeneous projective point arithmetic. )
REQUIRE stdlib/script-fragments.fth

: secp256k1-field ( script -- script )
    bytes-hex fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f bsv-num-be
;
: secp256k1-order ( script -- script )
    bytes-hex fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 bsv-num-be
;
: secp256k1-gx ( script -- script )
    bytes-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 bsv-num-be
;
: secp256k1-gy ( script -- script )
    bytes-hex 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 bsv-num-be
;
: secp256k1-reduce ( script -- script ) op-depth op-1sub op-pick op-mod ;

: secp256k1-endomorphism-x ( script -- script )
    ( X becomes beta*X mod p. The caller leaves Y and Z unchanged. )
    bytes-hex 7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee bsv-num-be
    op-mul secp256k1-reduce
;

: secp256k1-lattice-a1 ( script -- script ) bytes-hex 3086d221a7d46bcde86c90e49284eb15 bsv-num-be ;
: secp256k1-lattice-a2 ( script -- script ) bytes-hex 0114ca50f7a8e2f3f657c1108d9d44cfd8 bsv-num-be ;
: secp256k1-lattice-minus-b1 ( script -- script ) bytes-hex e4437ed6010e88286f547fa90abfe4c3 bsv-num-be ;

: secp256k1-lambda-split ( script -- script )
    ( Input k is in 0..n. Return signed k1 and k2 with k1+lambda*k2 = k mod n. )
    ( The lattice has b2=a1. Positive division rounds with an added floor of n/2. )
    secp256k1-order op-dup op-2 op-div
    2 script-pick-depth secp256k1-lattice-a1 op-mul op-over op-add
    2 script-pick-depth op-div ( k n halfN c1 )
    3 script-pick-depth secp256k1-lattice-minus-b1 op-mul 2 script-pick-depth op-add
    3 script-pick-depth op-div ( k n halfN c1 c2 )

    4 script-pick-depth 2 script-pick-depth secp256k1-lattice-a1 op-mul op-sub
    op-over secp256k1-lattice-a2 op-mul op-sub ( k1 = k-c1*a1-c2*a2 )
    2 script-pick-depth secp256k1-lattice-minus-b1 op-mul
    2 script-pick-depth secp256k1-lattice-a1 op-mul op-sub ( k2 = -c1*b1-c2*b2 )
    op-toaltstack op-toaltstack
    2 script-drop-pairs op-drop
    2 script-restore-items
;

: secp256k1-add ( script -- script )
    ( Complete homogeneous addition. Preserve the stack below the two points. )
    ( The caller places the field prime at the bottom of the main stack. )
    ( zz = z1*z2 and k = 21*xz, with xz = x1*z2+x2*z1. )
    3 script-pick-depth op-over op-mul
    op-over 7 script-pick-depth op-mul 4 script-pick-depth 6 script-pick-depth op-mul op-add
    21 bsv-num op-dup op-rot op-mul

    ( yy = y1*y2, h = 21*zz and minus = yy-h. )
    7 script-pick-depth 5 script-pick-depth op-mul op-2swap op-mul op-2dup op-sub

    ( Stage the terms of xy. Consume y and z to form yz = y1*z2+y2*z1. )
    6 script-pick-depth 9 script-pick-depth op-mul 10 script-pick-depth 7 script-pick-depth op-mul
    op-7 op-roll op-9 op-roll op-mul op-9 op-roll op-8 op-roll op-mul op-add

    ( X = xy*minus-yz*k. )
    op-dup 7 script-pick-depth op-mul op-2swap op-add
    op-dup 4 script-pick-depth op-mul op-rot op-sub secp256k1-reduce

    ( t = 3*x1*x2, zr = xy*t, plus = yy+h. )
    op-8 op-roll op-8 op-roll op-mul op-3 op-mul op-rot op-over op-mul
    op-6 op-roll op-6 op-roll op-add

    ( Y = minus*plus+t*k. Z = yz*plus+zr. )
    op-rot op-6 op-roll op-mul op-over op-6 op-roll op-mul op-add secp256k1-reduce
    op-4 op-roll op-rot op-mul op-rot op-add secp256k1-reduce
;

: secp256k1-add-affine ( script -- script )
    ( Complete addition with right-hand Z=1. Input: X1 Y1 Z1 x2 y2. )
    ( The caller places the field prime at the bottom of the main stack. )

    ( Stage x1*y2 and compute yz = y1+z1*y2. )
    4 script-pick-depth op-over op-mul op-over 4 script-pick-depth op-mul 5 script-pick-depth op-add

    ( h = 21*z1, k = 21*xz, where xz = x1+z1*x2. )
    21 bsv-num op-dup 6 script-pick-depth op-mul
    5 script-pick-depth op-7 op-roll op-mul 8 script-pick-depth op-add op-rot op-mul

    ( t = 3*x1*x2, yr = t*k, xy = x1*y2+x2*y1 and zr = xy*t. )
    op-7 op-roll 6 script-pick-depth op-mul op-3 op-mul op-2dup op-mul
    op-7 op-roll 8 script-pick-depth op-mul op-6 op-roll op-add op-rot op-over op-mul

    ( X = xy*minus-yz*k, where minus = yy-h. )
    op-7 op-roll op-7 op-roll op-mul op-dup 6 script-pick-depth op-sub
    op-3 op-roll op-over op-mul 7 script-pick-depth op-6 op-roll op-mul op-sub secp256k1-reduce

    ( Y = minus*plus+yr, where plus = yy+h. Z = yz*plus+zr. )
    op-rot op-5 op-roll op-add op-rot op-over op-mul op-4 op-roll op-add secp256k1-reduce
    op-4 op-roll op-rot op-mul op-3 op-roll op-add secp256k1-reduce
;

: secp256k1-double-x ( script -- script )
    ( Specialize complete addition using X^3 = Y^2*Z - 7*Z^3. )
    ( Infinity stays valid because X=Z=0 and Y is nonzero. )
    ( Emit X' above the intermediate terms needed for Y' and Z'. )
    ( Keep yz = Y*Z, yy = Y^2, t = 21*Z^2 and q = 3*t. )
    op-2dup op-mul op-over op-rot op-mul 2 script-pick-depth op-dup op-mul
    21 bsv-num op-rot op-mul op-3 op-over op-mul

    ( Save yy+2*q for Y'. Use yy-q as the second factor of X'. )
    op-dup op-over op-add 3 script-pick-depth op-add
    3 script-pick-depth 2 script-pick-depth op-sub
    op-7 op-roll op-7 op-roll op-mul op-2 op-mul op-mul
;

: secp256k1-double-yz ( script -- script )
    ( Y' is yy times the saved sum minus q*t. )
    4 script-pick-depth op-rot op-mul op-2swap op-mul op-sub secp256k1-reduce

    ( Z' = 8*Y^3*Z. )
    op-2swap op-mul op-8 op-mul secp256k1-reduce
;

: secp256k1-double ( script -- script )
    secp256k1-double-x secp256k1-reduce secp256k1-double-yz
;

: secp256k1-double-pair ( script -- script )
    ( The second doubling uses X' only as a linear factor. Reduce it once, after both doublings. )
    ( Starting with reduced coordinates, both doublings keep X within 226 ScriptNum bytes. )
    secp256k1-double-x secp256k1-double-yz secp256k1-double
;
