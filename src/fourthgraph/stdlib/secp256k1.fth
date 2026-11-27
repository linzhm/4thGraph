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

: secp256k1-reduce-point-coordinate ( script cell cell -- script )
    ( Build arguments: field placement and its depth at this reduction. )
    ( Placement 0 uses the bottom of the main stack. Placement 1 uses the item below the point operands. )
    swap 0= if drop secp256k1-reduce else script-pick-depth op-mod then
;

: secp256k1-beta ( script -- script )
    bytes-hex 7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee bsv-num-be
;

: secp256k1-endomorphism-x ( script -- script )
    ( X becomes beta*X mod p. The caller leaves Y and Z unchanged. )
    secp256k1-beta op-mul secp256k1-reduce
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

: secp256k1-add-with-field ( script cell -- script )
    ( Complete homogeneous addition. Preserve the stack below the two points. )
    swap
    ( Compute xy = x1*y2+x2*y1, t = 3*x1*x2 and zr = xy*t. )
    op-over 6 script-pick-depth op-mul 3 script-pick-depth 6 script-pick-depth op-mul op-add
    op-3 7 script-pick-depth 5 script-pick-depth op-mul op-mul op-2dup op-mul

    ( Consume both X coordinates to compute xz = x1*z2+x2*z1 and k = 21*xz. )
    21 bsv-num op-9 op-roll 5 script-pick-depth op-mul
    op-7 op-roll 8 script-pick-depth op-mul op-add op-over op-mul

    ( h = 21*z1*z2. Form plus = y1*y2+h and minus = y1*y2-h. )
    7 script-pick-depth 6 script-pick-depth op-mul op-rot op-mul
    8 script-pick-depth 7 script-pick-depth op-mul op-2dup op-add op-swap op-rot op-sub

    ( Compute Y = minus*plus+t*k, then consume y and z to get yz. )
    op-2dup op-mul op-5 op-roll 4 script-pick-depth op-mul op-add
    op-9 op-roll op-7 op-roll op-mul op-7 op-roll op-8 op-roll op-mul op-add

    ( Reduce X = xy*minus-yz*k and the staged Y. Compute Z = yz*plus+zr. )
    op-rot op-6 op-roll op-mul op-over op-5 op-roll op-mul op-sub
    over 5 secp256k1-reduce-point-coordinate op-rot over 5 secp256k1-reduce-point-coordinate
    op-2swap op-mul op-3 op-roll op-add swap 3 secp256k1-reduce-point-coordinate
;

: secp256k1-add ( script -- script ) 0 secp256k1-add-with-field ;

: secp256k1-add-affine-with-field ( script cell -- script )
    ( Complete addition with right-hand Z=1. Input: X1 Y1 Z1 x2 y2. )
    swap

    ( Form t = 3*x1*x2, xy = x1*y2+x2*y1 and zr = xy*t. )
    op-over 5 script-pick-depth op-mul op-3 op-mul
    op-over 6 script-pick-depth op-mul 3 script-pick-depth 6 script-pick-depth op-mul op-add
    op-2dup op-mul

    ( Form xz = x1+z1*x2 and k = 21*xz. )
    21 bsv-num 6 script-pick-depth op-6 op-roll op-mul op-8 op-roll op-add op-over op-mul

    ( Combine yy = y1*y2 and h = 21*z1. Consume y and z to form yz = y1+z1*y2. )
    7 script-pick-depth 6 script-pick-depth op-mul op-rot 7 script-pick-depth op-mul
    op-2dup op-sub op-8 op-roll op-8 op-roll op-mul op-8 op-roll op-add
    op-2swap op-add ( plus = yy+h, with minus = yy-h underneath yz. )

    ( Stage yz*plus for Z. Compute X = xy*minus-yz*k. )
    op-2dup op-mul op-rot 4 script-pick-depth op-mul
    op-6 op-roll 4 script-pick-depth op-mul op-swap op-sub
    over 7 secp256k1-reduce-point-coordinate

    ( Y = minus*plus+t*k. Z = yz*plus+zr. )
    op-2swap op-mul op-5 op-roll op-4 op-roll op-mul op-add
    over 4 secp256k1-reduce-point-coordinate
    op-2swap op-add swap 3 secp256k1-reduce-point-coordinate
;

: secp256k1-add-affine ( script -- script ) 0 secp256k1-add-affine-with-field ;

: secp256k1-scale-root ( script -- script )
    ( u satisfies 21*u^6 = 1 modulo p. Scaling by u^2 and u^3 gives 3*b = 1. )
    bytes-hex 7e8c32a50d81affef6014528bdbdfe776653b213d485953c3801f2356ad9d755 bsv-num-be
;

: secp256k1-scale-affine-pair ( script -- script )
    ( x1 y1 x2 y2 -> the same pair on the scaled curve. The field prime is at stack bottom. )
    ( Compute A = u^2, then multiply both x coordinates by A. )
    secp256k1-scale-root op-dup op-over op-mul secp256k1-reduce
    op-5 op-roll op-over op-mul secp256k1-reduce
    op-over op-5 op-roll op-mul
    ( Compute B = A*u and scale both y coordinates. )
    op-2swap op-mul secp256k1-reduce
    op-4 op-roll op-over op-mul secp256k1-reduce
    op-rot secp256k1-reduce op-rot op-4 op-roll op-mul secp256k1-reduce
;

: secp256k1-scaled-add-with-field ( script cell -- script )
    ( Complete homogeneous addition on the curve with 3*b = 1. )
    swap
    ( Compute yz, xz and the two cross products yz*xz and 3*x1*x2*xz. )
    op-over 4 script-pick-depth op-mul op-over 6 script-pick-depth op-mul op-add
    op-over 7 script-pick-depth op-mul 5 script-pick-depth 5 script-pick-depth op-mul op-add
    op-2dup op-mul op-3 9 script-pick-depth 7 script-pick-depth op-mul op-mul
    op-rot op-over op-mul

    ( Consume the x coordinates for xy and stage zr = xy*3*x1*x2. )
    op-9 op-roll 6 script-pick-depth op-mul 9 script-pick-depth op-8 op-roll op-mul op-add
    op-rot op-over op-mul

    ( Form yy = y1*y2, h = z1*z2, plus = yy+h and minus = yy-h. )
    op-8 op-roll op-7 op-roll op-mul op-7 op-roll op-7 op-roll op-mul
    op-2dup op-add op-7 op-roll op-over op-mul op-2swap op-sub

    ( X = xy*minus-yz*xz. Y = minus*plus+3*x1*x2*xz. Z = yz*plus+zr. )
    op-rot op-over op-mul op-2swap op-add op-2swap op-mul op-4 op-roll op-sub
    over 4 secp256k1-reduce-point-coordinate
    op-2swap op-add over 3 secp256k1-reduce-point-coordinate
    op-rot swap 3 secp256k1-reduce-point-coordinate
;

: secp256k1-scaled-add-affine-with-field ( script cell -- script )
    ( Complete addition on the scaled curve with right-hand Z = 1. )
    swap
    ( Form xy, t = 3*x1*x2 and zr = xy*t. )
    op-over 4 script-pick-depth op-mul op-over 6 script-pick-depth op-mul op-add
    op-3 6 script-pick-depth 4 script-pick-depth op-mul op-mul op-2dup op-mul
    ( Form xz = x1+z1*x2 and yz = y1+z1*y2, then t*xz and yz*xz. )
    5 script-pick-depth op-5 op-roll op-mul op-7 op-roll op-add op-rot op-over op-mul
    5 script-pick-depth 5 script-pick-depth op-mul 7 script-pick-depth op-add
    op-rot op-over op-mul
    ( With h = z1, compute minus = yy-h and plus = yy+h. )
    op-7 op-roll op-6 op-roll op-mul op-dup 7 script-pick-depth op-sub
    op-swap op-7 op-roll op-add
    ( Finish X, Y and Z with the same formulas as the projective case. )
    op-2dup op-mul op-rot op-7 op-roll op-mul op-3 op-roll op-sub
    op-2swap op-mul op-swap over 5 secp256k1-reduce-point-coordinate
    op-2swap op-add over 4 secp256k1-reduce-point-coordinate
    op-2swap op-add swap 3 secp256k1-reduce-point-coordinate
;

: secp256k1-double-x-with-coefficient ( script cell -- script )
    ( Build argument: curve coefficient multiplied by three. )
    ( Use the curve equation to eliminate X^3 from complete addition. )
    ( Infinity stays valid because X=Z=0 and Y is nonzero. )
    ( Emit X' above the intermediate terms needed for Y' and Z'. )
    swap
    op-2dup op-mul op-over op-rot op-mul 2 script-pick-depth op-dup op-mul
    ( Keep yz = Y*Z, yy = Y^2, t = 3*b*Z^2 and q = 3*t. )
    swap dup 1 = if drop op-swap else bsv-num op-rot op-mul then
    op-3 op-over op-mul

    ( Save yy+2*q for Y'. Use yy-q as the second factor of X'. )
    op-dup op-over op-add 3 script-pick-depth op-add
    3 script-pick-depth 2 script-pick-depth op-sub
    op-7 op-roll op-7 op-roll op-mul op-2 op-mul op-mul
;

: secp256k1-double-x ( script -- script ) 21 secp256k1-double-x-with-coefficient ;

: secp256k1-double-yz-with-field ( script cell -- script )
    ( Y' is yy times the saved sum minus q*t. )
    swap 4 script-pick-depth op-rot op-mul op-2swap op-mul op-sub
    over 4 secp256k1-reduce-point-coordinate

    ( Z' = 8*Y^3*Z. )
    op-2swap op-mul op-8 op-mul swap 3 secp256k1-reduce-point-coordinate
;

: secp256k1-double-with-coefficient ( script cell cell -- script )
    ( Build arguments: field placement and curve coefficient multiplied by three. )
    rot swap secp256k1-double-x-with-coefficient over 6 secp256k1-reduce-point-coordinate
    swap secp256k1-double-yz-with-field
;

: secp256k1-double-with-field ( script cell -- script ) 21 secp256k1-double-with-coefficient ;

: secp256k1-double ( script -- script ) 0 secp256k1-double-with-field ;

: secp256k1-double-pair-with-coefficient ( script cell cell -- script )
    ( The second doubling uses X' only as a linear factor. Reduce it once, after both doublings. )
    ( With coefficient 1 or 21 and reduced input, both doublings keep X within 226 ScriptNum bytes. )
    rot over secp256k1-double-x-with-coefficient
    rot swap over secp256k1-double-yz-with-field
    rot rot swap secp256k1-double-with-coefficient
;

: secp256k1-double-pair-with-field ( script cell -- script ) 21 secp256k1-double-pair-with-coefficient ;

: secp256k1-double-pair ( script -- script ) 0 secp256k1-double-pair-with-field ;

: secp256k1-scaled-double-with-field ( script cell -- script ) 1 secp256k1-double-with-coefficient ;

: secp256k1-scaled-double-pair-with-field ( script cell -- script ) 1 secp256k1-double-pair-with-coefficient ;
