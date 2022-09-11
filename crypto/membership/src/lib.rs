use ff::Field;

use dalek_ff_group::EdwardsPoint;
use minimal_proof25519::scalar::Scalar;

use bellman::{
  SynthesisError, ConstraintSystem,
  gadgets::{Assignment, num::AllocatedNum},
};

mod math;
use crate::math::input_num;

mod ecc;
use crate::ecc::{Point, PrivatePoint, edwards_basepoint_mul};

#[cfg(test)]
mod tests;

// TODO: Merkle tree
pub(crate) fn verify_presence<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  tree: AllocatedNum<Scalar>,
  y: AllocatedNum<Scalar>,
) -> Result<(), SynthesisError> {
  cs.enforce(|| "root", |lc| lc + y.get_variable(), |lc| lc + CS::one(), |lc| lc + tree.get_variable());
  Ok(())
}

#[derive(Clone, Copy)]
pub struct TonyProvingData {
  original: Point,
  blind: Scalar,
}

pub fn tony<CS: ConstraintSystem<Scalar>>(mut cs: CS, tree: Scalar, output: EdwardsPoint, data: Option<TonyProvingData>) -> Result<(), SynthesisError> {
  let tree = input_num(cs.namespace(|| "tree"), tree)?;
  let output = PrivatePoint::from(cs.namespace(|| "output"), Point::from(output))?;

  // Have it be negative to subtract it, re-acquiring the original point
  let blind_neg = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(-data.unwrap().blind))?;
  let original = edwards_basepoint_mul(cs.namespace(|| "unblind"), output, blind_neg)?;

  // TODO: original.normalize()
  verify_presence(cs.namespace(|| "merkle proof"), tree, original.y)
}

#[test]
fn test() {
  use rand_core::OsRng;

  use ff::PrimeField;
  use group::Group;
  use dalek_ff_group::{Scalar as EdwardsScalar, ED25519_BASEPOINT_TABLE};

  use bellman::gadgets::test::TestConstraintSystem;

  let mut cs = TestConstraintSystem::new();

  let original = EdwardsPoint::random(&mut OsRng);
  let edwards_blind = EdwardsScalar::random(&mut OsRng);
  let output = original + (&ED25519_BASEPOINT_TABLE * edwards_blind);

  let output_var = PrivatePoint::from(cs.namespace(|| "output"), Point::from(output)).unwrap();
  let blind = Scalar::from_repr(edwards_blind.to_repr()).unwrap();
  let blind_var = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(-blind)).unwrap();
  let tree = edwards_basepoint_mul(cs.namespace(|| "blind mul"), output_var, blind_var).unwrap().y.get_value().unwrap();

  tony(cs.namespace(|| "tony"), tree, output, Some(TonyProvingData { original: Point::from(original), blind })).unwrap();
  assert!(cs.is_satisfied());
}
