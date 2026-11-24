# Verifier design

The lock fixes the verification key and the ordered public scalars. The unlock supplies $A$, $B$, $C$, a field residue and the affine slopes required by the selected experiment. The script checks coordinate ranges, curve membership and prime-order subgroup membership. For each affine step, it checks that the denominator is nonzero and verifies the slope equation in the field.

The G1 subgroup test uses $\phi(P)=-[u^2]P$. The Miller loop already calculates $[u]B$, so the G2 test reuses that result and verifies $\psi(B)=-[u]B$. Here $u$ is the absolute value of the BLS12-381 seed. The host also validates the verification key before generating the script. IC entries and their linear combination may be the identity. A circuit may have zero public inputs. [zkcrypto subgroup design notes](https://docs.rs/bls12_381/latest/bls12_381/notes/design/index.html)

## Pairing equation

Let $p$ be the base field characteristic and $r$ the scalar field order. The verifier precomputes $VK_x=IC_0+\sum_i x_i IC_i$ and the product of the fixed Miller terms for $(-\alpha,\beta)$ and $(-VK_x,\gamma)$. It also prepares the lines for the fixed second argument $\delta$. The script computes the variable Miller terms for $(A,B)$ and $(-C,\delta)$. Let $M$ be the product of all four terms in the positive-seed convention.

The sextic twist tower is defined by $i^2=-1$ and $w^6=1+i$. A line with affine slope $\lambda$ and starting point $(x_T,y_T)$ contributes $(\lambda x_T-y_T)-\lambda x_P w^2+y_Pw^3$. The positive seed computes the inverse pairing after final exponentiation. Rescaling and the omitted vertical denominator contribute factors in proper subfields that vanish under the final exponent. The same convention for all four terms preserves the identity test. [Groth16 paper](https://eprint.iacr.org/2016/260) · [Bitcoin Script pairing implementation](https://eprint.iacr.org/2024/1498)

## Residue check and fusion

The pairing equation is $M^{(p^{12}-1)/r}=1$. Write $H=p^6+1$ and $e=p+u$. For BLS12-381, $\gcd(e,H)=r$. For nonzero $X$, the projection $X^{1-p^6}$ lies in the cyclic group of order $H$. Its kernel is $\mathbb{F}_{p^6}^{*}$.

The script checks $Mz^e\in\mathbb{F}_{p^6}^{*}$. It requires zero odd coefficients in the $w$ basis and a nonzero even coefficient.

- **Soundness.** The projection of $Mz^e$ is 1. The projected $z^e$ has order dividing $H/r$, so the projected $M$ does too. This gives $M^{(1-p^6)H/r}=1$, equivalent to the pairing equation.
- **Completeness.** If the pairing equation holds, the projected $M$ has order dividing $H/r$. With $k=e^{-1}\bmod(H/r)$, choose $z=M^{-k}$. The projection of $Mz^e$ is 1 and the product is nonzero.

Starting the Miller accumulator at $z$ and multiplying it by $z$ on set bits reuses its squarings to compute $z^u$. Frobenius computes the remaining multiplier $z^p$. The reference host verifies the pairing equation through direct final exponentiation. Tests compare the tower multiplication with a schoolbook implementation.

## Projective experiments

Beta computes the G1 endomorphism test with Jacobian coordinates $x=X/Z^2$, $y=Y/Z^3$. It computes $[u^2]P$ using a fixed chain and compares coordinates after cross-multiplying by $Z^2$ and $Z^3$. The proper nonzero coefficients in this chain lie below the G1 prime order, so valid finite inputs avoid exceptional mixed additions. A zero $Z$ is absorbing in both formulas. The verifier requires a nonzero final $Z$. This removes 272 G1 slope coordinates. [Explicit Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html)

Gamma uses Jacobian coordinates over $\mathbb{F}_{p^2}$ for the variable G2 Miller operand. The doubling line is scaled by $2YZ^3$, and the mixed-addition line by $(x_2Z^2-X)Z^3$. The final nonzero $Z$ ensures each scale was nonzero. The residue check projects away these $\mathbb{F}_{p^2}$ factors, so the same affine host product supplies the residue witness for all three experiments. Gamma removes all 136 remaining slope coordinates. The fixed delta lines stay prepared off chain.

Beta and gamma load each repeated large ScriptNum constant once and use OP_PICK for later references. This keeps more constants on the stack and reduces total bytecode.

## Optimization directions

| Direction | Measurement or proof obligation |
|---|---|
| Fuse the residue check with the Miller accumulator | Implemented. This saves 60,257 locking bytes with the same unlock and reduces local verification time. |
| Join the two sparse lines before accumulating | Implemented. This saves another 28,156 locking bytes and takes slightly longer in chain-gang. |
| Reuse prepared constants on the script stack | Implemented in beta and gamma. A future commitment layout needs to authenticate the full constant sequence before use and measure both script halves. |
| Reduce the affine slope payload | Implemented with projective G1 in beta and projective G1 and G2 in gamma. The smallest unlock is 980 bytes. |
| Support transaction-dependent public inputs | Benchmark a fixed-base window for $VK_x$ at the public input widths of interest. A covenant wrapper must authenticate each scalar against the spending transaction. |
| Amortize verification across token outputs | Test one verifier input per transfer and an authenticated relation to each covered output index and amount. Measure funding, payment and later spend together. |
