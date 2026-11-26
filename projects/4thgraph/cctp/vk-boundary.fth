( Dynamic CCTP verifier with a transaction boundary at the authenticated VK point. )

bsv-effect: read-proof -- proof ;
: read-proof read-g1 read-g2 read-g1 read-fp12 pack-proof ;

bsv-effect: bind-claim public-claim -- gamma-term ;
: bind-claim 2 bind-windowed-public-inputs-fp2 ;

bsv-effect: check-proof-points proof -- proof ;
: check-proof-points check-a-subgroup check-c-subgroup check-b-curve ;

bsv-effect: check-pairing-residue miller-state -- ;
: check-pairing-residue
    check-b-subgroup combine-residue check-residue-subfield require-nonzero-residue
;

bsv-effect: check-pairing gamma-term proof -- ;
: check-pairing check-proof-points miller-loop check-pairing-residue ;

bsv-effect: groth16-verify -- ;
: groth16-verify read-public-claim read-proof swap bind-claim swap check-pairing ;

bsv-effect: groth16-msm -- ;
: groth16-msm read-public-claim bind-claim drop ;

( The transaction wrapper authenticates the claim before invoking this entry. )
bsv-effect: groth16-pairing -- ;
: groth16-pairing
    read-public-claim read-proof swap use-certified-public-claim swap check-pairing
;
