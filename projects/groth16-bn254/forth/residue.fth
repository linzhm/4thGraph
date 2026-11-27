: require-pairing-product ( bn254-product -- bn254-checked )
    bn254-mul-fixed-residue-factor
    bn254-mul-residue-frobenius
    bn254-require-fp12-one
;
