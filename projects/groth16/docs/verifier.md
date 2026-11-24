# Verifier design

The lock fixes the verification key and the ordered public scalars. The unlock supplies (A), (B), (C), a field residue and affine slopes. The host calculates the slopes and residue when it encodes the unlock. The script independently checks the supplied values. The proof points must be finite affine BLS12-381 points in the prime-order subgroups. The host also validates the verification key before generating a script. A circuit may have zero public inputs, and IC entries and their linear combination can be the identity.

The script checks coordinate range and curve membership. For each affine step it requires a nonzero denominator and verifies the slope equation in the field. It checks the (G_1) subgroup via the endomorphism relation (phi(P)=-[u^2]P). The Miller loop already calculates ([u]B), so the (G_2) check reuses that point and verifies (psi(B)=-[u]B). Here (u) is the absolute value of the BLS12-381 seed. See the [zkcrypto subgroup design notes](https://docs.rs/bls12_381/latest/bls12_381/notes/design/index.html).

## Pairing equation

Let (p) be the base field characteristic and (r) the Groth16 scalar order. The verifier precomputes (VK_x=IC_0+sum_i x_iIC_i) and the product of the fixed Miller terms for ((-alpha,eta)) and ((-VK_x,gamma)). It also prepares the lines for the fixed second argument (delta). The script computes the variable Miller terms for ((A,B)) and ((-C,delta)). Let (M) be the product of all four terms with the same positive-seed convention.

The implementation uses the sextic twist tower (i^2=-1), (w^6=1+i). A line with affine slope (lambda) and starting point ((x_T,y_T)) contributes ((lambda x_T-y_T)-lambda x_Pw^2+y_Pw^3). The line rescaling and the omitted vertical denominator lie in proper subfields, and the final exponent kills those factors. The positive seed computes the inverse pairing under final exponentiation. Applying the same convention to all four terms preserves the identity test. See the [Groth16 paper](https://eprint.iacr.org/2016/260) and the [Bitcoin Script pairing implementation](https://eprint.iacr.org/2024/1498).

## Residue check and fusion

The Groth16 pairing equation is (M^{(p^{12}-1)/r}=1). Write (H=p^6+1) and (e=p+u). For BLS12-381, (gcd(e,H)=r). For any nonzero (X) in the extension field, (X^{1-p^6}) lies in the cyclic group of order (H). The kernel of this projection is (mathbb F_{p^6}^{*}).

The script checks (M z^einmathbb F_{p^6}^{*}). Membership requires zero odd coefficients in the (w) basis and at least one nonzero even coefficient.

- **Soundness.** Applying the projection to (M z^e) gives 1. The projected (z^e) has order dividing (H/r), so the projected (M) also has order dividing (H/r). Raising (M) to ((1-p^6)H/r) gives 1, which is equivalent to the required final exponent test.
- **Completeness.** If the final exponent test holds, the projected (M) has order dividing (H/r). With (k=e^{-1}mod(H/r)), choose (z=M^{-k}). The projection of (M z^e) is 1, and the product is nonzero.

Starting the Miller accumulator at (z) and multiplying by (z) on set bits reuses the same squarings to compute (z^u). The remaining multiplier is (z^p), which can be computed using the Frobenius map. The reference host also verifies the pairing equation with direct final exponentiation. The tests compare the tower multiplication to a separate schoolbook implementation.

## Projective experiments

Beta computes the G1 endomorphism test with Jacobian points \(x=X/Z^2, y=Y/Z^3\). It computes \([u^2]P\) with a fixed addition chain and compares coordinates by cross-multiplying against \(Z^2\) and \(Z^3\). The range of all proper nonzero coefficients in this chain lies below the prime order of G1, so valid finite inputs avoid the exceptional mixed additions. For malformed points, a zero \(Z\) is absorbing in both formulas. The verifier requires a nonzero final \(Z\). This removes 272 G1 slope coordinates. [Explicit Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html)

Gamma uses the same Jacobian formulas over Fp2 for the variable G2 Miller operand. The doubling line is scaled by \(2YZ^3\), and the mixed addition line by \((x_2Z^2-X)Z^3\). Every factor is in Fp2. The final nonzero \(Z\) proves each factor was nonzero, and the residue check projects away Fp2 factors. The same affine host product therefore supplies the residue witness for all three experiments. Gamma removes all 136 remaining slope coordinates. The fixed delta lines stay prepared off chain.

Beta and gamma also place repeated large ScriptNum constants on the main stack once. Bytecode uses OP_PICK for later references. This trades stack residency for smaller scripts while leaving the proof data and field arithmetic unchanged.

## Optimization directions

| Direction | Measurement or proof obligation |
|---|---|
| Fuse the residue check with the Miller accumulator | Implemented. On the vector, it saves 60,257 locking bytes with the same unlock and reduces local verification time. |
| Join the two sparse lines before accumulating | Implemented. It saves another 28,156 locking bytes, but the local verifier is slightly slower. Benchmark both profiles on the target node before choosing. |
| Reuse prepared constants on the script stack | Implemented for beta and gamma. A future commitment layout should measure both script halves and authenticate its full constant sequence before use. |
| Reduce the affine slope payload | Implemented with projective G1 in beta and projective G1 and G2 in gamma. The smallest unlock is 980 bytes. |
| Support transaction-dependent public inputs | Add a bound on public input width and benchmark a fixed-base window for (VK_x). A covenant wrapper must derive or authenticate each public scalar from the actual spending transaction. Measure this variant independently of the fixed-statement profile. |
| Amortize verification across token outputs | Test a single verifier input per transfer with an authenticated relation to every covered output index and amount. Measure payment, change, setup and later spend bytes together, and preserve independent progress for disjoint input sets. |

For proof-only experiments, the same proof can be presented anywhere the same statement is used. A spendable payment or PELS design needs a separate binding that gives the proof meaning for its specific transaction.
