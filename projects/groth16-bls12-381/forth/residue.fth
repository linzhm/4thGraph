: verify-residue ( groth16-miller-state -- groth16-verified )
    ( Combine the Miller accumulator, key factor, and Frobenius of z. )
    bls12-381-miller-factors
    bls12-381-frobenius-residue
    bls12-381-residue-product
    bls12-381-require-fp6
    bls12-381-require-nonzero
;
