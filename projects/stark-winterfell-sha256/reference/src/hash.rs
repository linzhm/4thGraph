use sha2::{Digest as _, Sha256 as Sha2};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use winterfell::{
    crypto::{Digest, ElementHasher, Hasher},
    math::{FieldElement, fields::f128::BaseElement},
};

const BYTES: u8 = 0;
const FIELD_ELEMENTS: u8 = 1;
const MERKLE_PARENT: u8 = 2;
const DIGEST_LIST: u8 = 3;
const DIGEST_WITH_U64: u8 = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Sha256Digest([u8; 32]);

impl Digest for Sha256Digest {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Serializable for Sha256Digest {
    fn write_into<W: ByteWriter>(&self, writer: &mut W) {
        writer.write_bytes(&self.0);
    }
}

impl Deserializable for Sha256Digest {
    fn read_from<R: ByteReader>(reader: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(reader.read_array()?))
    }
}

// Pass canonical field encodings straight into SHA-256 without allocating a buffer.
struct TaggedSha256(Sha2);

impl TaggedSha256 {
    fn new(domain: u8) -> Self {
        let mut state = Sha2::new();
        state.update([domain]);
        Self(state)
    }

    fn finish(self) -> Sha256Digest {
        Sha256Digest(self.0.finalize().into())
    }
}

impl ByteWriter for TaggedSha256 {
    fn write_u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

pub(crate) struct Sha256;

impl Hasher for Sha256 {
    type Digest = Sha256Digest;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let mut state = TaggedSha256::new(BYTES);
        state.write_bytes(bytes);
        state.finish()
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut state = TaggedSha256::new(MERKLE_PARENT);
        state.write_bytes(&values[0].0);
        state.write_bytes(&values[1].0);
        state.finish()
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut state = TaggedSha256::new(DIGEST_LIST);
        for digest in values {
            state.write_bytes(&digest.0);
        }
        state.finish()
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut state = TaggedSha256::new(DIGEST_WITH_U64);
        state.write_bytes(&seed.0);
        state.write_bytes(&value.to_le_bytes());
        state.finish()
    }
}

impl ElementHasher for Sha256 {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = BaseElement>>(elements: &[E]) -> Self::Digest {
        let mut state = TaggedSha256::new(FIELD_ELEMENTS);
        for element in elements {
            element.write_into(&mut state);
        }
        state.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fourthgraph_stark_counter::{prove, verify};
    use winterfell::crypto::hashers::Blake3_256;

    fn hex_bytes(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_tagged_sha256_vectors() {
        let vectors = include_str!("../../versions/v0.1.0/hash-vectors.txt");
        for row in vectors.lines() {
            let mut fields = row.split_ascii_whitespace();
            let name = fields.next().unwrap();
            let packet = hex_bytes(fields.next().unwrap());
            let computed = match name {
                "bytes" => Sha256::hash(&packet),
                "trace-row" => {
                    let elements: Vec<_> = packet
                        .chunks_exact(16)
                        .map(|part| BaseElement::new(u128::from_le_bytes(part.try_into().unwrap())))
                        .collect();
                    Sha256::hash_elements(&elements)
                }
                "merkle-parent" => {
                    let right = hex_bytes(fields.next().unwrap());
                    Sha256::merge(&[
                        Sha256Digest(packet.try_into().unwrap()),
                        Sha256Digest(right.try_into().unwrap()),
                    ])
                }
                "digest-list" => {
                    let digests: Vec<_> = packet
                        .chunks_exact(32)
                        .map(|part| Sha256Digest(part.try_into().unwrap()))
                        .collect();
                    Sha256::merge_many(&digests)
                }
                "seed-counter" => {
                    let encoded = hex_bytes(fields.next().unwrap());
                    let counter = u64::from_le_bytes(encoded.try_into().unwrap());
                    Sha256::merge_with_int(Sha256Digest(packet.try_into().unwrap()), counter)
                }
                _ => panic!("unknown SHA-256 fixture: {name}"),
            };
            assert_eq!(
                computed.as_bytes().as_slice(),
                hex_bytes(fields.next().unwrap()),
                "{name}"
            );
            assert!(fields.next().is_none());
        }
    }

    #[test]
    fn proof_profiles_are_distinct() {
        type Blake3 = Blake3_256<BaseElement>;

        let current = u32::MAX;
        let (next, sha256_proof) = prove::<Sha256>(current).unwrap();
        let (blake3_next, blake3_proof) = prove::<Blake3>(current).unwrap();
        assert_eq!(next, blake3_next);
        verify::<Sha256>(current, next, &sha256_proof).unwrap();
        verify::<Blake3>(current, next, &blake3_proof).unwrap();
        assert!(verify::<Sha256>(current, next, &blake3_proof).is_err());
        assert!(verify::<Blake3>(current, next, &sha256_proof).is_err());
    }
}
