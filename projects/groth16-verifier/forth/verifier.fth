REQUIRE BSV
REQUIRE public-inputs.fth
REQUIRE miller.fth
REQUIRE residue.fth

: verify-proof ( -- groth16-verified )
    prepare-pairing
    miller-pairing
    verify-residue
;
