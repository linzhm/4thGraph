: prepare-pairing ( -- groth16-pairing-key groth16-checked-g1 )
    bls12-381-read-witness
    swap bls12-381-check-g1-points
    swap bls12-381-check-public-inputs swap
;
