REQUIRE r1-math-scalar.fth

( Independent mathematical entry. No wire encoding or spending context. )

: r1-field-coordinate ( script -- script )
    op-dup op-0 r1-prime op-within op-verify
;

: r1-check-public-point ( script -- script )
    ( Runtime suffix: x y r s e -- x y r s e. )
    op-4 op-pick r1-field-coordinate op-4 op-pick r1-field-coordinate
    r1-curve-equation op-0 op-numequalverify
;

: r1-check-signature-scalars ( script -- script )
    op-2 op-pick op-1 r1-order op-within op-verify
    op-over op-1 r1-order op-within op-verify
;

: r1-signature-weights ( script -- script )
    ( Runtime: x y r s e -- x y r u v. Invert s here. )
    op-swap r1-order op-swap r1-inverse
    op-dup op-toaltstack
    op-mul r1-order op-mod
    op-fromaltstack op-2 op-pick op-mul r1-order op-mod
;

: r1-multiply-public-point ( script -- script )
    ( Runtime: x y r u v -- r vQ | alt: u. )
    op-toaltstack op-toaltstack op-rot op-rot
    op-fromaltstack op-fromaltstack op-swap op-toaltstack op-rot op-rot
    op-1 r1-scalar-multiply
;

: r1-multiply-generator ( script -- script )
    ( Runtime: push uG, consuming u from alt. )
    op-fromaltstack r1-generator r1-scalar-multiply
;

: r1-verification-point ( script -- script )
    ( Runtime: x y r u v -- r R. )
    r1-multiply-public-point r1-multiply-generator r1-point-add
;

: r1-check-result ( script -- script )
    ( Runtime: r X Y finite -- flag. Infinity cannot verify a signature. )
    op-if op-drop r1-order op-mod op-numequal
    op-else op-2drop op-drop op-0 op-endif
;

: r1-verify ( script -- script )
    ( Runtime: x y r s e -- flag. e is an unsigned 256-bit digest integer. )
    op-depth op-5 op-numequalverify
    r1-prime r1-constant-b
    bsv-empty op-6 op-roll 5 bsv-repeat-code bsv-cat-code
    r1-check-public-point
    r1-check-signature-scalars
    r1-signature-weights
    r1-verification-point
    r1-check-result
    op-nip op-nip
;
