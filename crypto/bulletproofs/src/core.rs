// Required to be for this entire file, which isn't an issue, as it wouldn't bind to the static
#![allow(non_upper_case_globals)]

use std::{mem, cell::Cell, sync::Once};

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use subtle::{Choice, ConditionallySelectable};

use generic_array::{typenum::U33, GenericArray};
use blake2::{digest::{Digest, Update, VariableOutput}, Blake2s256, Blake2bVar};

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use minimal_proof25519::{scalar::Scalar, point::Point};

pub(crate) use crate::{Commitment, scalar_vector::*};

pub(crate) const MAX_M: usize = 16;
pub(crate) const LOG_N: usize = 6; // 2 << 6 == N
pub(crate) const N: usize = 64;
const MAX_MN: usize = MAX_M * N;

#[allow(non_snake_case)]
pub(crate) struct Generators {
  pub(crate) G: Vec<Point>,
  pub(crate) H: Vec<Point>,
}

// TODO: Use wide reduction so this doesn't have a chance at failure and can become constant time
pub(crate) fn hash_to_scalar(buf: &[u8]) -> Scalar {
  let mut repr = [0; 32];
  repr.copy_from_slice(Blake2s256::digest(buf).as_ref());

  for _ in 0 .. 512 {
    let scalar = Scalar::from_repr(repr);
    if scalar.is_some().into() {
      return scalar.unwrap();
    }
    let new = Blake2s256::digest(repr);
    repr.copy_from_slice(new.as_ref());
  }
  panic!("Couldn't hash to a scalar");
}

// Rejection-sampling-based hash to point
// TODO: Cache successfully generated generators
fn generator(dst: &[u8], i: usize) -> Point {
  for attempt in 0 .. 10000u16 {
    let mut repr = <Point as GroupEncoding>::Repr::default();

    let mut digest = Blake2bVar::new(repr.len()).unwrap();
    digest.update(dst);
    digest.update(&u64::try_from(i).unwrap().to_le_bytes());
    digest.update(&attempt.to_le_bytes());

    digest.finalize_variable(&mut repr).unwrap();
    let point = Point::from_bytes(&repr);
    if point.is_some().into() {
      return point.unwrap().mul_by_cofactor();
    }
  }
  panic!("Couldn't generate a generator");
}

static mut GENERATORS: (Cell<mem::MaybeUninit<Generators>>, Once) =
  (Cell::new(mem::MaybeUninit::uninit()), Once::new());
pub(crate) fn generators() -> &'static Generators {
  unsafe {
    GENERATORS.1.call_once(|| {
      let mut generators = Generators { G: vec![], H: vec![] };
      for i in 0 .. MAX_MN {
        generators.G.push(generator(b"Bulletproofs G", i));
        generators.H.push(generator(b"Bulletproofs H", i));
      }
      GENERATORS.0.set(mem::MaybeUninit::new(generators));
    });
    &*(*GENERATORS.0.as_ptr()).as_ptr()
  }
}

lazy_static! {
  pub(crate) static ref H: Point = generator(b"H", 0);
}

pub(crate) fn vector_exponent(a: &ScalarVector, b: &ScalarVector) -> Point {
  debug_assert_eq!(a.len(), b.len());
  (a * &generators().G[.. a.len()]) + (b * &generators().H[.. b.len()])
}

pub(crate) fn hash_cache(cache: &mut Scalar, mash: &[GenericArray<u8, U33>]) -> Scalar {
  let slice =
    &[cache.to_repr().as_ref(), mash.iter().cloned().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  *cache = hash_to_scalar(slice);
  *cache
}

pub(crate) fn MN(outputs: usize) -> (usize, usize, usize) {
  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_M) && (M < outputs)
  } {
    logM += 1;
  }

  (logM + LOG_N, M, M * N)
}

pub(crate) fn bit_decompose(commitments: &[Commitment]) -> (ScalarVector, ScalarVector) {
  let (_, M, MN) = MN(commitments.len());

  let sv = commitments.iter().map(|c| Scalar::from(c.amount)).collect::<Vec<_>>();
  let mut aL = ScalarVector::new(MN);
  let mut aR = ScalarVector::new(MN);

  for j in 0 .. M {
    for i in (0 .. N).rev() {
      let mut bit = Choice::from(0);
      if j < sv.len() {
        bit = Choice::from((sv[j].to_repr()[i / 8] >> (i % 8)) & 1);
      }
      aL.0[(j * N) + i] = Scalar::conditional_select(&Scalar::zero(), &Scalar::one(), bit);
      aR.0[(j * N) + i] = Scalar::conditional_select(&-Scalar::one(), &Scalar::zero(), bit);
    }
  }

  (aL, aR)
}

pub(crate) fn hash_commitments(commitments: &[Point]) -> Scalar {
  hash_to_scalar(&commitments.iter().flat_map(|V| V.to_bytes()).collect::<Vec<_>>())
}

pub(crate) fn alpha_rho<R: RngCore + CryptoRng>(
  rng: &mut R,
  aL: &ScalarVector,
  aR: &ScalarVector,
) -> (Scalar, Point) {
  let ar = Scalar::random(rng);
  (ar, (vector_exponent(aL, aR) + (Point::generator() * ar)))
}

pub(crate) fn LR_statements(
  a: &ScalarVector,
  G_i: &[Point],
  b: &ScalarVector,
  H_i: &[Point],
  cL: Scalar,
  U: Point,
) -> Vec<(Scalar, Point)> {
  let mut res = a
    .0
    .iter()
    .cloned()
    .zip(G_i.iter().cloned())
    .chain(b.0.iter().cloned().zip(H_i.iter().cloned()))
    .collect::<Vec<_>>();
  res.push((cL, U));
  res
}

lazy_static! {
  pub(crate) static ref TWO_N: ScalarVector = ScalarVector::powers(Scalar::from(2u8), N);
}

pub(crate) fn challenge_products(w: &[Scalar], winv: &[Scalar]) -> Vec<Scalar> {
  let mut products = vec![Scalar::zero(); 1 << w.len()];
  products[0] = winv[0];
  products[1] = w[0];
  for j in 1 .. w.len() {
    let mut slots = (1 << (j + 1)) - 1;
    while slots > 0 {
      products[slots] = products[slots / 2] * w[j];
      products[slots - 1] = products[slots / 2] * winv[j];
      slots = slots.saturating_sub(2);
    }
  }

  // Sanity check as if the above failed to populate, it'd be critical
  for w in &products {
    debug_assert!(!bool::from(w.is_zero()));
  }

  products
}
