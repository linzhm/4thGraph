REQUIRE forth/statement.fth

: verify-bn254-proof ( -- bn254-verified )
    bn254-owner-guard
    deployment-statement
    bn254-msm-and-pairing
;
