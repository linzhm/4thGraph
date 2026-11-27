use std::{error::Error, marker::PhantomData};

use winterfell::{
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree, RandomCoin},
    math::{FieldElement, ToElements, fields::f128::BaseElement},
    matrix::ColMatrix,
};

const TRACE_WIDTH: usize = 2;
const TRACE_LENGTH: usize = 1024;
const LAST_ROW: usize = TRACE_LENGTH - 1;
const U32_MODULUS: u128 = 1 << 32;

struct PublicInputs {
    current: BaseElement,
    next: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.current, self.next]
    }
}

struct CounterAir {
    context: AirContext<BaseElement>,
    inputs: PublicInputs,
}

impl Air for CounterAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = [2, 2].map(TransitionConstraintDegree::new).to_vec();
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
            inputs,
        }
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let state = frame.current()[0];
        let inverse = frame.current()[1];
        let distance = state - E::from(u32::MAX);
        let delta = frame.next()[0] - state - E::ONE;
        let modulus = E::from(BaseElement::new(U32_MODULUS));

        // A nonzero delta is possible only at u32::MAX, where delta must be -2^32.
        result[0] = distance * delta;
        result[1] = modulus * (distance * inverse - E::ONE) - delta;
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        vec![
            Assertion::single(0, 0, self.inputs.current),
            Assertion::single(0, LAST_ROW, self.inputs.next),
        ]
    }
}

fn trace_row(row: &mut [BaseElement], value: u32) {
    let state = BaseElement::from(value);
    let distance = state - BaseElement::from(u32::MAX);
    row[0] = state;
    row[1] = distance.inv();
}

struct CounterProver<H>(ProofOptions, PhantomData<H>);

impl<H: ElementHasher<BaseField = BaseElement> + Sync> Prover for CounterProver<H> {
    type BaseField = BaseElement;
    type Air = CounterAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<H>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            current: trace.get(0, 0),
            next: trace.get(0, LAST_ROW),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.0
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partition: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace: CompositionPolyTrace<E>,
        columns: usize,
        domain: &StarkDomain<BaseElement>,
        partition: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(trace, columns, domain, partition)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a Self::Air,
        aux_rand: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand, coefficients)
    }
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        40,
        8,
        16,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn prove<H: ElementHasher<BaseField = BaseElement> + Sync>(
    current: u32,
) -> Result<(u32, Vec<u8>), Box<dyn Error>> {
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    trace.fill(
        |row| trace_row(row, current),
        |step, row| trace_row(row, current.wrapping_add((step + 1) as u32)),
    );
    let proof = CounterProver::<H>(proof_options(), PhantomData).prove(trace)?;
    Ok((current.wrapping_add(LAST_ROW as u32), proof.to_bytes()))
}

pub fn verify<H: ElementHasher<BaseField = BaseElement>>(
    current: u32,
    next: u32,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let proof = parse_proof(bytes)?;
    verify_proof::<H, DefaultRandomCoin<H>>(current, next, proof)
}

pub(crate) fn parse_proof(bytes: &[u8]) -> Result<Proof, Box<dyn Error>> {
    let proof = Proof::from_bytes(bytes)?;
    if proof.trace_info() != &TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH) {
        return Err("proof has incompatible counter trace metadata".into());
    }
    // Require the canonical encoding, including the end of the buffer.
    if proof.to_bytes() != bytes {
        return Err("proof encoding is not canonical".into());
    }
    Ok(proof)
}

pub(crate) fn verify_proof<H, C>(
    current: u32,
    next: u32,
    proof: Proof,
) -> Result<(), Box<dyn Error>>
where
    H: ElementHasher<BaseField = BaseElement>,
    C: RandomCoin<BaseField = BaseElement, Hasher = H>,
{
    let inputs = PublicInputs {
        current: BaseElement::from(current),
        next: BaseElement::from(next),
    };
    let options = winterfell::AcceptableOptions::OptionSet(vec![proof_options()]);
    winterfell::verify::<CounterAir, H, C, MerkleTree<H>>(proof, inputs, &options)?;
    Ok(())
}
