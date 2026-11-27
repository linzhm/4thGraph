( Signed digits of 6*u^2 after the leading 1, in execution order. )
: g2-double ( bn254-ladder -- bn254-ladder )
    bn254-g2-double
;
: g2-add ( bn254-ladder -- bn254-ladder )
    bn254-g2-double bn254-g2-add-positive
;
: g2-sub ( bn254-ladder -- bn254-ladder )
    bn254-g2-double bn254-g2-add-negative
;
: require-g2-subgroup ( bn254-points -- bn254-subgroup )
    bn254-g2-start
    g2-double g2-double g2-sub g2-double g2-double g2-double g2-sub g2-double g2-add g2-double
    g2-add g2-double g2-double g2-sub g2-double g2-sub g2-double g2-double g2-double g2-double
    g2-double g2-add g2-double g2-double g2-add g2-double g2-double g2-add g2-double g2-double
    g2-add g2-double g2-double g2-double g2-sub g2-double g2-double g2-double g2-sub g2-double
    g2-sub g2-double g2-double g2-sub g2-double g2-double g2-double g2-add g2-double g2-sub
    g2-double g2-sub g2-double g2-add g2-double g2-double g2-double g2-double g2-double g2-double
    g2-sub g2-double g2-double g2-double g2-double g2-double g2-double g2-sub g2-double g2-double
    g2-double g2-double g2-add g2-double g2-double g2-double g2-double g2-sub g2-double g2-add
    g2-double g2-add g2-double g2-sub g2-double g2-sub g2-double g2-add g2-double g2-double
    g2-double g2-double g2-add g2-double g2-sub g2-double g2-double g2-sub g2-double g2-add
    g2-double g2-double g2-double g2-add g2-double g2-double g2-double g2-double g2-sub g2-double
    g2-add g2-double g2-double g2-double g2-double g2-double g2-sub g2-double g2-add g2-double
    g2-add g2-double g2-double g2-add g2-double g2-sub g2-double
    bn254-g2-require-frobenius
;
