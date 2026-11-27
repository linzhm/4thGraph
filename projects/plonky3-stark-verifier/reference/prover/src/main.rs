//! Generate and natively verify the two fixed Fibonacci AIR proof profiles.

use std::{env, fs, path::Path};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};

const LOG_TRACE: usize = 4;
const LOG_BLOWUP: usize = 3;
const QUERIES: usize = 64;
type Hash = [u8; 32];

fn field_bytes<F: PrimeField64>(value: F) -> impl Iterator<Item = u8> {
    let width = if F::ORDER_U64 <= u32::MAX.into() {
        4
    } else {
        8
    };
    value
        .as_canonical_u64()
        .to_le_bytes()
        .into_iter()
        .take(width)
}

#[derive(Clone, Copy, Debug)]
struct LeafHash;

impl<F: PrimeField64> CryptographicHasher<F, Hash> for LeafHash {
    fn hash_iter<I: IntoIterator<Item = F>>(&self, input: I) -> Hash {
        Sha256.hash_iter(
            [0].into_iter()
                .chain(input.into_iter().flat_map(field_bytes)),
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct NodeHash;

impl PseudoCompressionFunction<Hash, 2> for NodeHash {
    fn compress(&self, [left, right]: [Hash; 2]) -> Hash {
        Sha256.hash_iter([1].into_iter().chain(left).chain(right))
    }
}

#[derive(Clone, Debug)]
struct Transcript<F> {
    pending: Vec<u8>,
    field: std::marker::PhantomData<F>,
}

impl<F> Transcript<F> {
    fn new(domain: &[u8]) -> Self {
        Self {
            pending: domain.to_vec(),
            field: std::marker::PhantomData,
        }
    }

    fn squeeze(&mut self) -> Hash {
        let digest = Sha256.hash_iter([2].into_iter().chain(self.pending.drain(..)));
        self.pending.extend(digest);
        digest
    }
}

impl<F: PrimeField64> CanObserve<F> for Transcript<F> {
    fn observe(&mut self, value: F) {
        self.pending.extend(field_bytes(value));
    }
}

impl<F: PrimeField64> CanObserve<MerkleCap<F, Hash>> for Transcript<F> {
    fn observe(&mut self, cap: MerkleCap<F, Hash>) {
        assert_eq!(cap.roots().len(), 1);
        self.pending.extend(cap.roots()[0]);
    }
}

impl<F: PrimeField64> CanSample<F> for Transcript<F> {
    fn sample(&mut self) -> F {
        self.squeeze().into_iter().rev().fold(F::ZERO, |acc, byte| {
            acc * F::from_u16(256) + F::from_u8(byte)
        })
    }
}

impl<F: PrimeField64 + BinomiallyExtendable<D>, const D: usize>
    CanSample<BinomialExtensionField<F, D>> for Transcript<F>
{
    fn sample(&mut self) -> BinomialExtensionField<F, D> {
        self.sample_algebra_element()
    }
}

impl<F: PrimeField64> CanSampleBits<usize> for Transcript<F> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < usize::BITS as usize);
        let digest = self.squeeze();
        let word = u64::from_le_bytes(digest[..8].try_into().unwrap());
        (word & ((1 << bits) - 1)) as usize
    }
}

impl<F: PrimeField64> FieldChallenger<F> for Transcript<F> {}

impl<F: PrimeField64> GrindingChallenger for Transcript<F> {
    type Witness = F;

    fn grind(&mut self, bits: usize) -> F {
        assert_eq!(bits, 0, "these proof profiles have no grinding round");
        F::ZERO
    }
}

struct Fibonacci {
    shifted_trace: bool,
}

impl<F> BaseAir<F> for Fibonacci {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for Fibonacci {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let [a, b, last] = builder.public_values().try_into().unwrap();

        let offset = AB::Expr::from_bool(self.shifted_trace);
        let mut first = builder.when_first_row();
        first.assert_eq(local[0], a);
        first.assert_eq(local[1] - offset.clone(), b);

        let mut transition = builder.when_transition();
        transition.assert_eq(local[1] - offset.clone(), next[0]);
        transition.assert_eq(local[0] + local[1], next[1]);

        builder.when_last_row().assert_eq(local[1] - offset, last);
    }
}

type BaseMmcs<F> = MerkleTreeMmcs<F, u8, LeafHash, NodeHash, 2, 32>;
type Ext<F, const D: usize> = BinomialExtensionField<F, D>;
type ExtMmcs<F, const D: usize> = ExtensionMmcs<F, Ext<F, D>, BaseMmcs<F>>;
type Pcs<F, const D: usize> = TwoAdicFriPcs<F, Radix2DitParallel<F>, BaseMmcs<F>, ExtMmcs<F, D>>;
type Config<F, const D: usize> = StarkConfig<Pcs<F, D>, Ext<F, D>, Transcript<F>>;

fn append_extension<F: PrimeField64, E: BasedVectorSpace<F>>(packet: &mut Vec<u8>, values: &[E]) {
    packet.extend(
        values
            .iter()
            .flat_map(BasedVectorSpace::as_basis_coefficients_slice)
            .copied()
            .flat_map(field_bytes),
    );
}

fn export<F: PrimeField64 + TwoAdicField + BinomiallyExtendable<D>, const D: usize>(
    proof: &Proof<Config<F, D>>,
) -> Vec<u8> {
    let mut packet = Vec::new();
    let opened = &proof.opened_values;
    let fri = &proof.opening_proof;
    assert_eq!(proof.degree_bits, LOG_TRACE);
    assert_eq!(opened.quotient_chunks.len(), 1);
    assert_eq!(fri.commit_phase_commits.len(), LOG_TRACE);
    assert_eq!(fri.final_poly.len(), 1);
    assert_eq!(fri.query_proofs.len(), QUERIES);
    for commitment in [&proof.commitments.trace, &proof.commitments.quotient_chunks]
        .into_iter()
        .chain(&fri.commit_phase_commits)
    {
        assert_eq!(commitment.roots().len(), 1);
        packet.extend(commitment.roots()[0]);
    }
    for values in [
        &opened.trace_local,
        opened.trace_next.as_ref().unwrap(),
        &opened.quotient_chunks[0],
        &fri.final_poly,
    ] {
        append_extension::<F, _>(&mut packet, values);
    }
    for query in &fri.query_proofs {
        assert_eq!(query.input_proof.len(), 2);
        assert_eq!(query.commit_phase_openings.len(), LOG_TRACE);
        for (opening, width) in query.input_proof.iter().zip([2, D]) {
            assert_eq!(opening.opened_values.len(), 1);
            let row = &opening.opened_values[0];
            assert_eq!(row.len(), width);
            packet.extend(row.iter().copied().flat_map(field_bytes));
            assert_eq!(opening.opening_proof.len(), LOG_TRACE + LOG_BLOWUP);
            packet.extend(opening.opening_proof.iter().flatten());
        }
        for (round, step) in query.commit_phase_openings.iter().enumerate() {
            assert_eq!(step.log_arity, 1);
            assert_eq!(step.sibling_values.len(), 1);
            append_extension::<F, _>(&mut packet, &step.sibling_values);
            assert_eq!(step.opening_proof.len(), LOG_TRACE + LOG_BLOWUP - round - 1);
            packet.extend(step.opening_proof.iter().flatten());
        }
    }
    packet
}

fn generate<F: PrimeField64 + TwoAdicField + BinomiallyExtendable<D>, const D: usize>(
    domain: &[u8],
    a: u64,
    b: u64,
    output: &Path,
    shifted_trace: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if a >= F::ORDER_U64 || b >= F::ORDER_U64 {
        return Err("seeds must be canonical field elements".into());
    }
    let mmcs = BaseMmcs::new(LeafHash, NodeHash, 0);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtMmcs::new(mmcs),
    };
    let config = Config::new(
        Pcs::new(Radix2DitParallel::default(), mmcs, fri),
        Transcript::new(domain),
    );
    let mut left = F::from_u64(a);
    let mut right = F::from_u64(b);
    let offset = F::from_bool(shifted_trace);
    let mut trace = Vec::new();
    for _ in 0..1 << LOG_TRACE {
        trace.extend([left, right + offset]);
        (left, right) = (right, left + right);
    }
    let last = *trace.last().unwrap() - offset;
    let public = [F::from_u64(a), F::from_u64(b), last];
    let air = Fibonacci { shifted_trace };
    let proof = prove(&config, &air, RowMajorMatrix::new(trace, 2), &public);
    verify(&config, &air, &proof, &public)?;
    let standard_air = Fibonacci {
        shifted_trace: false,
    };
    if shifted_trace {
        // The PCS and transcript are valid for the exact same public values.
        // The standard verifier may reject this control only at the AIR check.
        if !matches!(
            verify(&config, &standard_air, &proof, &public),
            Err(p3_uni_stark::VerificationError::OodEvaluationMismatch { .. })
        ) {
            return Err("shifted AIR control did not reach the native quotient check".into());
        }
    } else {
        let wrong = [public[0], public[1], last + F::ONE];
        if verify(&config, &standard_air, &proof, &wrong).is_ok() {
            return Err("native verifier accepted an altered public result".into());
        }
    }
    fs::write(output, export(&proof))?;
    println!("{a} {b} {}", last.as_canonical_u64());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let (positionals, shifted_trace) = match args.as_slice() {
        [flag, rest @ ..] if flag == "--test-shifted-air" => (rest, true),
        rest => (rest, false),
    };
    let [profile, a, b, output] = positionals else {
        return Err("usage: fourthgraph-stark-prover [--test-shifted-air] {babybear|goldilocks} SEED_A SEED_B OUTPUT".into());
    };
    let (a, b, output) = (a.parse()?, b.parse()?, Path::new(output));
    match profile.as_str() {
        "babybear" => generate::<BabyBear, 4>(
            b"4thgraph/fibonacci-stark/v1/babybear",
            a,
            b,
            output,
            shifted_trace,
        ),
        "goldilocks" => generate::<Goldilocks, 2>(
            b"4thgraph/fibonacci-stark/v1/goldilocks",
            a,
            b,
            output,
            shifted_trace,
        ),
        _ => Err("unknown proof profile".into()),
    }
}
