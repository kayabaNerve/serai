use rand_core::OsRng;

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use dalek_ff_group::EdwardsPoint;
use minimal_proof25519::scalar::Scalar;

use bellman::{
  ConstraintSystem, Namespace,
  gadgets::{num::AllocatedNum, test::TestConstraintSystem},
};

use crate::ecc::{PrivatePoint, edwards_add};

#[test]
fn test_edwards_add() {
  let original = EdwardsPoint::random(&mut OsRng);
  let offset = EdwardsPoint::random(&mut OsRng);

  let to_private_point = |mut cs: Namespace<'_, _, _>, point: EdwardsPoint| {
    let (x, y) = point.decompose();
    let t = AllocatedNum::alloc(cs.namespace(|| "t"), || Ok(x * y)).unwrap();
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();
    let z = AllocatedNum::alloc(cs.namespace(|| "z"), || Ok(Scalar::one())).unwrap();
    PrivatePoint { x, y, z, t }
  };

  let mut cs = TestConstraintSystem::new();
  let priv_original = to_private_point(cs.namespace(|| "original"), original);
  let priv_offset = to_private_point(cs.namespace(|| "offset"), offset);
  let res = edwards_add(cs.namespace(|| "add"), priv_original, priv_offset).unwrap();

  let z = res.z.get_value().unwrap().invert().unwrap();
  let x = res.x.get_value().unwrap() * z;
  let y = res.y.get_value().unwrap() * z;

  let mut bytes = y.to_repr();
  bytes[31] |= x.is_odd().unwrap_u8() << 7;
  let res = EdwardsPoint::from_bytes(&bytes).unwrap();
  assert_eq!(original + offset, res);
}

#[test]
fn test_scalar_mul() {
  
}
