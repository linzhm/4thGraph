( Signed digits of 6*u+2 after the leading 1, in execution order. )
: miller-zero ( bn254-miller -- bn254-miller )
    bn254-miller-square bn254-miller-tangent-lines
;
: miller-plus ( bn254-miller -- bn254-miller )
    miller-zero bn254-miller-add-positive bn254-miller-fold-inverse
;
: miller-minus ( bn254-miller -- bn254-miller )
    miller-zero bn254-miller-add-negative bn254-miller-fold-residue
;
: miller-pairing ( bn254-inverse -- bn254-product )
    bn254-miller-start
    miller-zero miller-minus miller-zero miller-plus miller-zero miller-zero miller-zero miller-minus miller-zero miller-minus
    miller-zero miller-zero miller-zero miller-minus miller-zero miller-plus miller-zero miller-minus miller-zero miller-zero
    miller-minus miller-zero miller-zero miller-zero miller-zero miller-zero miller-plus miller-zero miller-zero miller-minus
    miller-zero miller-plus miller-zero miller-zero miller-minus miller-zero miller-zero miller-zero miller-zero miller-minus
    miller-zero miller-plus miller-zero miller-zero miller-zero miller-minus miller-zero miller-minus miller-zero miller-zero
    miller-plus miller-zero miller-zero miller-zero miller-minus miller-zero miller-zero miller-minus miller-zero miller-plus
    miller-zero miller-plus miller-zero miller-zero miller-zero
    bn254-miller-frobenius-lines
;
