use rand_core::OsRng;

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use dalek_ff_group::{Scalar as EdwardsScalar, EdwardsPoint};
use minimal_proof25519::scalar::Scalar;

use bellman::{ConstraintSystem, gadgets::{num::AllocatedNum, test::TestConstraintSystem}};

use crate::ecc::{PrivatePoint, edwards_add, edwards_basepoint_mul};

fn to_private_point<CS: ConstraintSystem<Scalar>>(mut cs: CS, point: EdwardsPoint) -> PrivatePoint {
  let (x, y) = point.decompose();
  let t = AllocatedNum::alloc(cs.namespace(|| "t"), || Ok(x * y)).unwrap();
  let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
  let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();
  let z = AllocatedNum::alloc(cs.namespace(|| "z"), || Ok(Scalar::one())).unwrap();
  PrivatePoint { x, y, z, t }
}

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
  let priv_original = to_private_point(cs.namespace(|| "original"), original);
  let priv_offset = to_private_point(cs.namespace(|| "offset"), offset);
  test(edwards_add(cs.namespace(|| "add"), priv_original, priv_offset).unwrap(), original + offset);
  assert!(cs.is_satisfied());
}

#[test]
fn test_scalar_mul() {
  let mut cs = TestConstraintSystem::new();

  let identity = PrivatePoint::identity(cs.namespace(|| "identity")).unwrap();
  let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Scalar::zero())).unwrap();
  test(edwards_basepoint_mul(cs.namespace(|| "zero mul"), identity.clone(), zero).unwrap(), EdwardsPoint::identity());

  let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(Scalar::one())).unwrap();
  test(edwards_basepoint_mul(cs.namespace(|| "one mul"), identity.clone(), one).unwrap(), EdwardsPoint::generator());

  let edwards_scalar = EdwardsScalar::random(&mut OsRng);
  let scalar = Scalar::from_repr(edwards_scalar.to_repr()).unwrap();
  let n = AllocatedNum::alloc(cs.namespace(|| "n"), || Ok(scalar)).unwrap();
  test(edwards_basepoint_mul(cs.namespace(|| "n mul"), identity.clone(), n).unwrap(), EdwardsPoint::generator() * edwards_scalar);

  assert!(cs.is_satisfied());
}
