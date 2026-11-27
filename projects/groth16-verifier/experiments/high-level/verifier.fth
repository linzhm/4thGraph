REQUIRE BSV

: prepare-pairing ( -- groth16-pairing-key groth16-checked-g1 )
    bls12-381-read-witness
    bls12-381-check-public-inputs
    swap bls12-381-check-g1-points
;

: miller-rounds ( groth16-miller-plan -- groth16-miller-plan )
    ( The accumulator starts at z for the leading bit of |u|. )
    ( Each bit squares the accumulator and multiplies by the tangent lines. )
    ( A one bit also includes the chord lines and multiplies by z. )
    bls12-381-miller-one-bit
    bls12-381-miller-zero-bit
    bls12-381-miller-one-bit
    2 0 DO bls12-381-miller-zero-bit LOOP
    bls12-381-miller-one-bit
    8 0 DO bls12-381-miller-zero-bit LOOP
    bls12-381-miller-one-bit
    31 0 DO bls12-381-miller-zero-bit LOOP
    bls12-381-miller-one-bit
    16 0 DO bls12-381-miller-zero-bit LOOP
;

: miller-pairing ( groth16-pairing-key groth16-checked-g1 -- groth16-miller-state )
    bls12-381-miller-begin
    miller-rounds
    bls12-381-miller-execute
;

: verify-residue ( groth16-miller-state -- groth16-verified )
    ( Combine the Miller accumulator, key factor, and Frobenius of z. )
    bls12-381-miller-factors
    bls12-381-frobenius-residue
    bls12-381-residue-product
    bls12-381-require-fp6
    bls12-381-require-nonzero
;

: verify-proof ( -- groth16-verified )
    prepare-pairing
    miller-pairing
    verify-residue
;
