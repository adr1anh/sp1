use std::{
    borrow::Borrow,
    fs::{self, File},
    io::Read,
    iter::{Skip, Take},
};

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_symmetric::CryptographicHasher;
use sp1_core_executor::{Executor, Program};
use sp1_core_machine::{io::SP1Stdin, reduce::SP1ReduceProof};
use sp1_recursion_circuit::machine::RootPublicValues;
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    stark::BabyBearPoseidon2Outer,
};
use sp1_stark::{baby_bear_poseidon2::MyHash as InnerHash, SP1CoreOpts, Word};

use crate::{InnerSC, SP1CoreProofData};

/// Get the SP1 vkey BabyBear Poseidon2 digest this reduce proof is representing.
pub fn sp1_vkey_digest_babybear(proof: &SP1ReduceProof<BabyBearPoseidon2Outer>) -> [BabyBear; 8] {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<BabyBear> = proof.public_values.as_slice().borrow();
    pv.sp1_vk_digest
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

pub fn root_public_values_digest(
    config: &InnerSC,
    public_values: &RootPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let input = (*public_values.sp1_vk_digest())
        .into_iter()
        .chain(
            (*public_values.committed_value_digest())
                .into_iter()
                .flat_map(|word| word.0.into_iter()),
        )
        .collect::<Vec<_>>();
    hash.hash_slice(&input)
}

pub fn assert_root_public_values_valid(
    config: &InnerSC,
    public_values: &RootPublicValues<BabyBear>,
) {
    let expected_digest = root_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest().iter().copied().zip_eq(expected_digest) {
        assert_eq!(value, expected);
    }
}

/// Assert that the digest of the public values is correct.
pub fn assert_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        assert_eq!(value, expected);
    }
}

impl SP1CoreProofData {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &SP1Stdin) -> u64 {
    let program = Program::from(elf).unwrap();
    let mut runtime = Executor::new(program, SP1CoreOpts::default());
    runtime.write_vecs(&stdin.buffer);
    runtime.run_fast().unwrap();
    runtime.state.global_clk
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    return words.iter().flat_map(|word| word.0).collect();
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

pub trait MaybeTakeIterator<I: Iterator>: Iterator<Item = I::Item> {
    fn maybe_skip(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Skip(self.skip(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }

    fn maybe_take(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Take(self.take(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }
}

impl<I: Iterator> MaybeTakeIterator<I> for I {}

pub enum RangedIterator<I> {
    Unbounded(I),
    Skip(Skip<I>),
    Take(Take<I>),
    Range(Take<Skip<I>>),
}

impl<I: Iterator> Iterator for RangedIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RangedIterator::Unbounded(unbounded) => unbounded.next(),
            RangedIterator::Skip(skip) => skip.next(),
            RangedIterator::Take(take) => take.next(),
            RangedIterator::Range(range) => range.next(),
        }
    }
}
