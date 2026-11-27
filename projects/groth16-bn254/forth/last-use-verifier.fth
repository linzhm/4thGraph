REQUIRE statement.fth
REQUIRE jacobian.fth
REQUIRE subgroup.fth
REQUIRE miller.fth
REQUIRE residue.fth

: check-bn254-proof-points ( bn254-loaded -- bn254-points )
    bn254-prime-check
    bn254-check-a
    bn254-check-c
    bn254-check-b
;

: verify-bn254-proof ( -- bn254-verified )
    bn254-owner-guard
    deployment-statement
    bn254-read-witness
    check-bn254-proof-points
    require-g2-subgroup
    bn254-bind-pairing-terms
    bn254-require-residue-inverse
    miller-pairing
    require-pairing-product
    bn254-emit-last-use
;
