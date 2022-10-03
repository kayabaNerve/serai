use bulletproof25519::scalar::Scalar;

use bellman::{
  ConstraintSystem,
  gadgets::{num::AllocatedNum, test::TestConstraintSystem},
};

use crate::math::{naive_add, naive_sub};

#[test]
fn test_basic_math() {
  let mut cs = TestConstraintSystem::new();
  let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Scalar::from(3u8))).unwrap();
  let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Scalar::from(5u8))).unwrap();
  assert_eq!(
    naive_add(cs.namespace(|| "+"), &a, &b).unwrap().get_value().unwrap(),
    Scalar::from(8u8)
  );
  assert_eq!(
    naive_sub(cs.namespace(|| "-"), &a, &b).unwrap().get_value().unwrap(),
    -Scalar::from(2u8)
  );
  assert_eq!(a.mul(cs.namespace(|| "*"), &b).unwrap().get_value().unwrap(), Scalar::from(15u8));
}
