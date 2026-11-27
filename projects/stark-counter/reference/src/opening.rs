use std::{cell::RefCell, error::Error};

use winterfell::{
    crypto::{DefaultRandomCoin, Digest, ElementHasher, MerkleTree, RandomCoin, RandomCoinError},
    math::{FieldElement, StarkField, fields::f128::BaseElement},
};

use crate::counter::{parse_proof, verify_proof};

thread_local! {
    static QUERY_POSITIONS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

// Use the standard coin for every draw and record Winterfell's final LDE positions.
struct RecordingCoin<H: ElementHasher>(DefaultRandomCoin<H>);

impl<H: ElementHasher<BaseField = BaseElement>> RandomCoin for RecordingCoin<H> {
    type BaseField = BaseElement;
    type Hasher = H;

    fn new(seed: &[BaseElement]) -> Self {
        Self(DefaultRandomCoin::new(seed))
    }

    fn reseed(&mut self, data: H::Digest) {
        self.0.reseed(data);
    }

    fn check_leading_zeros(&self, value: u64) -> u32 {
        self.0.check_leading_zeros(value)
    }

    fn draw<E: FieldElement<BaseField = BaseElement>>(&mut self) -> Result<E, RandomCoinError> {
        self.0.draw()
    }

    fn draw_integers(
        &mut self,
        count: usize,
        domain_size: usize,
        nonce: u64,
    ) -> Result<Vec<usize>, RandomCoinError> {
        let positions = self.0.draw_integers(count, domain_size, nonce)?;
        QUERY_POSITIONS.with_borrow_mut(|captured| captured.clone_from(&positions));
        Ok(positions)
    }
}

pub(crate) struct TraceOpening {
    pub index: usize,
    pub root: [u8; 32],
    pub row: Vec<u8>,
    pub path: Vec<u8>,
}

pub(crate) fn trace_opening<H>(
    current: u32,
    next: u32,
    query: usize,
    bytes: &[u8],
) -> Result<TraceOpening, Box<dyn Error>>
where
    H: ElementHasher<BaseField = BaseElement>,
{
    let proof = parse_proof(bytes)?;
    QUERY_POSITIONS.take();
    let verified = verify_proof::<H, RecordingCoin<H>>(current, next, proof.clone());
    let mut positions = QUERY_POSITIONS.take();
    verified?;

    // The verifier and prover serialize only the sorted unique queries.
    positions.sort_unstable();
    positions.dedup();
    if positions.len() != usize::from(proof.num_unique_queries) {
        return Err("captured queries do not match the proof".into());
    }
    let &index = positions
        .get(query)
        .ok_or("query ordinal is outside the proof")?;
    let domain_size = proof.lde_domain_size();
    let width = proof.trace_info().main_trace_width();
    let (trace_roots, _, _) = proof
        .commitments
        .parse::<H>(1, proof.fri_proof.num_layers())?;
    let root = trace_roots[0];
    let trace = proof
        .trace_queries
        .into_iter()
        .next()
        .ok_or("missing main trace queries")?;
    let (batch, table) =
        trace.parse::<BaseElement, H, MerkleTree<H>>(domain_size, positions.len(), width)?;
    let leaves: Vec<_> = table.rows().map(H::hash_elements).collect();
    let row = table
        .rows()
        .nth(query)
        .ok_or("missing trace row")?
        .iter()
        .flat_map(|element| element.as_int().to_le_bytes())
        .collect();
    let (leaf, siblings) = batch
        .into_openings(&leaves, &positions)?
        .into_iter()
        .nth(query)
        .ok_or("missing trace opening")?;
    MerkleTree::<H>::verify(root, index, leaf, &siblings)?;
    let path = siblings.iter().flat_map(Digest::as_bytes).collect();
    Ok(TraceOpening {
        index,
        root: root.as_bytes(),
        row,
        path,
    })
}
