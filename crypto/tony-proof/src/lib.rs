use ff::{Field, PrimeField};

use dalek_ff_group::{Scalar as EdwardsScalar, EdwardsPoint};
use minimal_proof25519::scalar::Scalar;

use bellman::{
  SynthesisError, ConstraintSystem, LinearCombination,
  gadgets::{boolean::Boolean, num::AllocatedNum, blake2s::blake2s},
};

mod math;
use crate::math::input_num;

mod ecc;
use crate::ecc::{PrivatePoint, edwards_basepoint_mul, invert};

#[cfg(test)]
mod tests;

// TODO: Merkle tree
pub(crate) fn verify_presence<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  tree: AllocatedNum<Scalar>,
  sign: Boolean,
  point: AllocatedNum<Scalar>,
) -> Result<(), SynthesisError> {
  let point_bits = point.to_bits_le(cs.namespace(|| "bits"))?;
  let bits =
    blake2s(cs.namespace(|| "leaf hash"), &[[sign].as_ref(), &point_bits].concat(), b"leafhash")?;

  // TODO: Tree

  // Convert the bits to a Scalar
  let mut lc = LinearCombination::zero();
  let mut coeff = Scalar::one();
  for bit in bits.iter().take(252) {
    lc = lc + &bit.lc(CS::one(), coeff);
    coeff = coeff.double();
  }

  // Verify the tree matches
  cs.enforce(|| "root", |_| lc, |lc| lc + CS::one(), |lc| lc + tree.get_variable());
  Ok(())
}

#[derive(Clone, Copy)]
pub struct TonyProvingData {
  blind: EdwardsScalar,
}

pub fn tony<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  tree: Scalar,
  output: EdwardsPoint,
  data: Option<TonyProvingData>,
) -> Result<(), SynthesisError> {
  let tree = input_num(cs.namespace(|| "tree"), tree)?;
  let output = PrivatePoint::from_edwards(cs.namespace(|| "output"), output)?;

  // Have it be negative to subtract it, re-acquiring the original point
  let (sign, point) = {
    let blind_neg = AllocatedNum::alloc(cs.namespace(|| "blind"), || {
      Ok(Scalar::from_repr((-data.unwrap().blind).to_repr()).unwrap())
    })?;
    let original = edwards_basepoint_mul(cs.namespace(|| "unblind"), output, blind_neg)?;

    // Normalize it
    let z_inv = invert(cs.namespace(|| "z invert"), original.z)?;
    let x = original.x.mul(cs.namespace(|| "x invert"), &z_inv)?;
    let y = original.y.mul(cs.namespace(|| "y invert"), &z_inv)?;

    // This to_bits_le is expensive given we only need a single bit, yet its the only secure way
    // to do this
    let is_odd = x.to_bits_le(cs.namespace(|| "bits"))?.swap_remove(0);
    (is_odd, y)
  };

  verify_presence(cs.namespace(|| "merkle proof"), tree, sign, point)
}

#[test]
fn test() {
  use rand_core::OsRng;
  use group::Group;
  use bellman::gadgets::{boolean::AllocatedBit, test::TestConstraintSystem};

  let mut cs = TestConstraintSystem::new();

  let original = EdwardsPoint::random(&mut OsRng);
  let blind = EdwardsScalar::random(&mut OsRng);
  let output = original + (EdwardsPoint::generator() * blind);

  let (x, y) = original.decompose();
  let sign = AllocatedBit::alloc(cs.namespace(|| "sign"), Some(x.is_odd().into())).unwrap();
  let y = input_num(cs.namespace(|| "y"), y).unwrap();
  let y = y.to_bits_le(cs.namespace(|| "bits")).unwrap();
  let bits = blake2s(
    cs.namespace(|| "leaf hash"),
    &[[Boolean::from(sign)].as_ref(), &y].concat(),
    b"leafhash",
  )
  .unwrap();

  let mut coeff = Scalar::one();
  let mut tree = Scalar::zero();
  for bit in bits.iter().take(252) {
    if bit.get_value().unwrap() {
      tree += coeff;
    }
    coeff = coeff.double();
  }

  tony(cs.namespace(|| "tony"), tree, output, Some(TonyProvingData { blind })).unwrap();
  assert!(cs.is_satisfied());
}
