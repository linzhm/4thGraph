( Dynamic CCTP verifier with a transaction boundary at the authenticated VK point. )

: read-proof ( -- proof ) read-g1 read-g2 read-g1 read-fp12 pack-proof ;

: bind-claim ( public-claim -- gamma-term ) 2 bind-windowed-public-inputs-fp2 ;

: check-proof-points ( proof -- proof ) check-a-subgroup check-c-subgroup check-b-curve ;

: check-pairing-residue ( miller-state -- )
    check-b-subgroup combine-residue check-residue-subfield require-nonzero-residue
;

: check-pairing ( gamma-term proof -- ) check-proof-points miller-loop check-pairing-residue ;

: groth16-verify ( -- ) read-public-claim read-proof swap bind-claim swap check-pairing ;

: groth16-msm ( -- ) read-public-claim bind-claim drop ;

( The transaction wrapper authenticates the claim before invoking this entry. )
: groth16-pairing ( -- )
    read-public-claim read-proof swap use-certified-public-claim swap check-pairing
;
