( BLS12-381 Groth16 verifier for fixed, mixed, or spend-time public inputs. )

: groth16-bls12-381-verify ( -- groth16-verified )
    bls12-381-read-witness
    bls12-381-check-public-inputs
    swap bls12-381-check-g1-points
    bls12-381-miller-loop
    bls12-381-check-residue
;
