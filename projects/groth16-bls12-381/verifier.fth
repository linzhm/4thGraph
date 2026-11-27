REQUIRE stdlib/groth16-bls12-381.fth

: verify-proof ( -- groth16-verified )
    groth16-bls12-381-verify
;
