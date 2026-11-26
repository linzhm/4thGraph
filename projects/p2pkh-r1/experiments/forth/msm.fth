( P-256 MSM. Compute u*G + v*Q with the standard fixed generator G. )
( The enclosing verifier checks that runtime Q is finite and on P-256. )
REQUIRE r1.fth

( Backend input: main p 3b r, alt ... u v Q.y Q.x. )
( The result uses homogeneous projective coordinates X:Y:Z. )

range: msm-scalar script-int 0
    $ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 ;
range: msm-affine script-int 0
    $ffffffff00000001000000000000000000000000ffffffffffffffffffffffff ;
range: msm-projective script-int
    $-ffffffff00000001000000000000000000000000fffffffffffffffffffffffe
    $ffffffff00000001000000000000000000000000ffffffffffffffffffffffff ;

: r1-msm-before ( script -- script )
    r1-prepare-lock r1-prepare-scalars
;

: r1-mul2 ( script script -- script )
    p256.mul2
;

: r1-msm-after ( script cell cell -- script )
    ( Build arguments are table slots and the number of cleanup pairs. )
    rot rot swap
    r1-check-point-start
    over 4 + bsv-num op-pick r1-check-point-low
    swap 3 + bsv-num op-pick r1-check-point-high
    bsv-empty r1-drop-two rot bsv-repeat-code bsv-cat-code
    r1-bind-transaction
;
