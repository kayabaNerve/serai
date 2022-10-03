use rand_core::OsRng;

use ff::{Field, PrimeField};
use group::Group;

use dalek_ff_group::{Scalar as EdwardsScalar, EdwardsPoint};
use minimal_proof25519::scalar::Scalar;

use bellman::{
  ConstraintSystem,
  gadgets::{num::AllocatedNum, test::TestConstraintSystem},
};

use crate::ecc::{PrivatePoint, edwards_add, edwards_basepoint_mul, invert};

fn test(calculated: PrivatePoint, actual: EdwardsPoint) {
  let z = calculated.z.get_value().unwrap().invert().unwrap();
  let x = calculated.x.get_value().unwrap() * z;
  let y = calculated.y.get_value().unwrap() * z;
  assert_eq!((x, y), actual.decompose());
}

#[test]
fn test_edwards_add() {
  let original = EdwardsPoint::random(&mut OsRng);
  let offset = EdwardsPoint::random(&mut OsRng);

  let mut cs = TestConstraintSystem::new();
  let priv_original = PrivatePoint::from_edwards(cs.namespace(|| "original"), original).unwrap();
  let priv_offset = PrivatePoint::from_edwards(cs.namespace(|| "offset"), offset).unwrap();
  test(edwards_add(cs.namespace(|| "add"), priv_original, priv_offset).unwrap(), original + offset);
  assert!(cs.is_satisfied());
}

#[test]
fn test_scalar_mul() {
  let mut cs = TestConstraintSystem::new();

  let identity = PrivatePoint::identity(cs.namespace(|| "identity")).unwrap();
  let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Scalar::zero())).unwrap();
  test(
    edwards_basepoint_mul(cs.namespace(|| "zero mul"), identity.clone(), zero).unwrap(),
    EdwardsPoint::identity(),
  );

  let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(Scalar::one())).unwrap();
  test(
    edwards_basepoint_mul(cs.namespace(|| "one mul"), identity.clone(), one).unwrap(),
    EdwardsPoint::generator(),
  );

  let edwards_scalar = EdwardsScalar::random(&mut OsRng);
  let scalar = Scalar::from_repr(edwards_scalar.to_repr()).unwrap();
  let n = AllocatedNum::alloc(cs.namespace(|| "n"), || Ok(scalar)).unwrap();
  test(
    edwards_basepoint_mul(cs.namespace(|| "n mul"), identity.clone(), n.clone()).unwrap(),
    EdwardsPoint::generator() * edwards_scalar,
  );

  let base = EdwardsPoint::random(&mut OsRng);
  let private_base = PrivatePoint::from_edwards(cs.namespace(|| "base"), base).unwrap();
  test(
    edwards_basepoint_mul(cs.namespace(|| "base + n mul"), private_base, n).unwrap(),
    base + (EdwardsPoint::generator() * edwards_scalar),
  );

  assert!(cs.is_satisfied());
}

#[test]
fn test_invert() {
  let mut cs = TestConstraintSystem::new();

  let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(Scalar::one())).unwrap();
  assert_eq!(
    invert(cs.namespace(|| "one inverse"), one).unwrap().get_value().unwrap(),
    Scalar::one()
  );

  let scalar = Scalar::random(&mut OsRng);
  let n = AllocatedNum::alloc(cs.namespace(|| "n"), || Ok(scalar)).unwrap();
  assert_eq!(
    invert(cs.namespace(|| "n inverse"), n).unwrap().get_value().unwrap(),
    scalar.invert().unwrap()
  );

  assert!(cs.is_satisfied());
}
