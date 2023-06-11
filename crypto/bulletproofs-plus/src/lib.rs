#![allow(non_snake_case)]

use std::collections::HashSet;

use zeroize::{Zeroize, ZeroizeOnDrop};

use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

mod scalar_vector;
pub use scalar_vector::{ScalarVector, weighted_inner_product};
mod scalar_matrix;
pub use scalar_matrix::ScalarMatrix;
mod point_vector;
pub use point_vector::PointVector;

pub mod weighted_inner_product;
pub mod single_range_proof;
pub mod aggregate_range_proof;

pub(crate) mod arithmetic_circuit_proof;
pub mod arithmetic_circuit;
pub mod gadgets;

#[cfg(any(test, feature = "tests"))]
pub mod tests;

pub const RANGE_PROOF_BITS: usize = 64;

pub(crate) enum GeneratorsList {
  GBold1,
  GBold2,
  HBold1,
}

// TODO: Table these
#[derive(Clone, Debug)]
pub struct Generators<T: Transcript, C: Ciphersuite> {
  pub(crate) g: C::G,
  pub(crate) h: C::G,
  pub(crate) g_bold1: PointVector<C>,
  pub(crate) g_bold2: PointVector<C>,
  h_bold1: PointVector<C>,
  h_bold2: PointVector<C>,

  // Uses a Vec<u8> since C::G doesn't impl Hash
  set: HashSet<Vec<u8>>,
  transcript: T,
}
impl<T: Transcript, C: Ciphersuite> Zeroize for Generators<T, C> {
  fn zeroize(&mut self) {
    self.g.zeroize();
    self.h.zeroize();
    self.g_bold1.zeroize();
    self.g_bold2.zeroize();
    self.h_bold1.zeroize();
    self.h_bold2.zeroize();
  }
}

impl<T: Transcript, C: Ciphersuite> Generators<T, C> {
  pub fn new(
    g: C::G,
    h: C::G,
    g_bold1: Vec<C::G>,
    g_bold2: Vec<C::G>,
    h_bold1: Vec<C::G>,
    h_bold2: Vec<C::G>,
  ) -> Self {
    assert!(!g_bold1.is_empty());
    assert_eq!(g_bold1.len(), g_bold2.len());
    assert_eq!(h_bold1.len(), h_bold2.len());
    assert_eq!(g_bold1.len(), h_bold1.len());

    let mut transcript = T::new(b"Bulletproofs+ Generators");

    transcript.domain_separate(b"generators");
    let mut set = HashSet::new();
    let mut add_generator = |label, generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      let bytes = generator.to_bytes();
      transcript.append_message(label, bytes);
      assert!(set.insert(bytes.as_ref().to_vec()));
    };

    add_generator(b"g", &g);
    add_generator(b"h", &h);
    for g in &g_bold1 {
      add_generator(b"g_bold1", g);
    }
    for g in &g_bold2 {
      add_generator(b"g_bold2", g);
    }
    for h in &h_bold1 {
      add_generator(b"h_bold1", h);
    }
    for h in &h_bold2 {
      add_generator(b"h_bold2", h);
    }

    Generators {
      g,
      h,
      g_bold1: PointVector(g_bold1),
      g_bold2: PointVector(g_bold2),
      h_bold1: PointVector(h_bold1),
      h_bold2: PointVector(h_bold2),
      set,
      transcript,
    }
  }

  pub(crate) fn new_without_secondaries(
    g: C::G,
    h: C::G,
    g_bold1: Vec<C::G>,
    h_bold1: Vec<C::G>,
  ) -> Self {
    assert!(!g_bold1.is_empty());
    assert_eq!(g_bold1.len(), h_bold1.len());

    let mut transcript = T::new(b"Bulletproofs+ Generators without secondaries");

    transcript.domain_separate(b"generators");
    let mut set = HashSet::new();
    let mut add_generator = |label, generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      let bytes = generator.to_bytes();
      transcript.append_message(label, bytes);
      assert!(set.insert(bytes.as_ref().to_vec()));
    };

    add_generator(b"g", &g);
    add_generator(b"h", &h);
    for g in &g_bold1 {
      add_generator(b"g_bold1", g);
    }
    for h in &h_bold1 {
      add_generator(b"h_bold1", h);
    }

    Generators {
      g,
      h,
      g_bold1: PointVector(g_bold1),
      g_bold2: PointVector(vec![]),
      h_bold1: PointVector(h_bold1),
      h_bold2: PointVector(vec![]),
      set,
      transcript,
    }
  }

  pub(crate) fn insert_generator(&mut self, list: GeneratorsList, index: usize, generator: C::G) {
    // Make sure this hasn't been used yet
    assert!(!self.g_bold2.0.is_empty());

    assert!(!bool::from(generator.is_identity()));

    let bytes = generator.to_bytes();
    self.transcript.domain_separate(b"inserted_generator");
    self.transcript.append_message(
      b"list",
      match list {
        GeneratorsList::GBold1 => b"g_bold1",
        GeneratorsList::GBold2 => b"g_bold2",
        GeneratorsList::HBold1 => b"h_bold1",
      },
    );
    self.transcript.append_message(b"index", u32::try_from(index).unwrap().to_le_bytes());
    self.transcript.append_message(b"generator", bytes);

    assert!(self.set.insert(bytes.as_ref().to_vec()));

    (match list {
      GeneratorsList::GBold1 => &mut self.g_bold1,
      GeneratorsList::GBold2 => &mut self.g_bold2,
      GeneratorsList::HBold1 => &mut self.h_bold1,
    })[index] = generator;
  }

  pub(crate) fn truncate(&mut self, generators: usize) {
    self.g_bold1.0.truncate(generators);
    self.g_bold2.0.truncate(generators);
    self.h_bold1.0.truncate(generators);
    self.h_bold2.0.truncate(generators);
    self
      .transcript
      .append_message(b"used_generators", u32::try_from(generators).unwrap().to_le_bytes());
  }

  pub fn reduce(mut self, generators: usize, with_secondaries: bool) -> Self {
    self.truncate(generators);
    if with_secondaries {
      self.transcript.append_message(b"secondaries", b"true");
      self.g_bold1.0.append(&mut self.g_bold2.0);
      self.h_bold1.0.append(&mut self.h_bold2.0);
    } else {
      self.transcript.append_message(b"secondaries", b"false");
      self.g_bold2.0.clear();
      self.h_bold2.0.clear();
    }
    self
  }

  pub(crate) fn g(&self) -> C::G {
    self.g
  }

  pub fn h(&self) -> C::G {
    self.h
  }

  pub(crate) fn g_bold(&self) -> &PointVector<C> {
    &self.g_bold1
  }

  pub(crate) fn h_bold(&self) -> &PointVector<C> {
    &self.h_bold1
  }

  pub(crate) fn g_bold2(&self) -> &PointVector<C> {
    &self.g_bold2
  }

  pub(crate) fn h_bold2(&self) -> &PointVector<C> {
    &self.h_bold2
  }

  pub(crate) fn debug_does_not_have(&self, other: C::G) {
    debug_assert!(!self.set.contains(other.to_bytes().as_ref()));
  }

  pub fn decompose(self) -> (C::G, C::G, PointVector<C>, PointVector<C>) {
    assert!(self.g_bold2.0.is_empty());
    (self.g, self.h, self.g_bold1, self.h_bold1)
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RangeCommitment<C: Ciphersuite> {
  pub value: u64,
  pub mask: C::F,
}

impl<C: Ciphersuite> RangeCommitment<C> {
  pub fn zero() -> Self {
    RangeCommitment { value: 0, mask: C::F::ZERO }
  }

  pub fn new(value: u64, mask: C::F) -> Self {
    RangeCommitment { value, mask }
  }

  pub fn masking<R: RngCore + CryptoRng>(rng: &mut R, value: u64) -> Self {
    RangeCommitment { value, mask: C::F::random(rng) }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self, g: C::G, h: C::G) -> C::G {
    (g * C::F::from(self.value)) + (h * self.mask)
  }
}

// Returns the little-endian decomposition.
fn u64_decompose<C: Ciphersuite>(value: u64) -> ScalarVector<C> {
  let mut bits = ScalarVector::<C>::new(64);
  for bit in 0 .. 64 {
    bits[bit] = C::F::from((value >> bit) & 1);
  }
  bits
}
