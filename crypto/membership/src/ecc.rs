use dalek_ff_group::EDWARDS_D;
use minimal_proof25519::scalar::Scalar;

use bellman::{SynthesisError, ConstraintSystem, gadgets::num::AllocatedNum};

use crate::math::{naive_add, naive_sub};

#[derive(Clone, Copy)]
pub(crate) struct Point {
  x: Scalar,
  y: Scalar,
  z: Scalar,
  t: Scalar,
}

pub(crate) struct PrivatePoint {
  pub(crate) x: AllocatedNum<Scalar>,
  pub(crate) y: AllocatedNum<Scalar>,
  pub(crate) z: AllocatedNum<Scalar>,
  pub(crate) t: AllocatedNum<Scalar>,
}

// TODO: This is Edwards. Shouldn't we use the Montgomery form?
// TODO: This is complete. Can we get away with the Z=1 variant (even just for one of them)?
// add-2008-hwcd-3
pub(crate) fn edwards_add<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: PrivatePoint,
  b: PrivatePoint,
) -> Result<PrivatePoint, SynthesisError> {
  #[allow(non_snake_case)]
  let A = {
    let ayx = naive_sub(cs.namespace(|| "A ayx"), &a.y, &a.x)?;
    let byx = naive_sub(cs.namespace(|| "A byx"), &b.y, &b.x)?;
    ayx.mul(cs.namespace(|| "A"), &byx)?
  };

  #[allow(non_snake_case)]
  let B = {
    let ayx = naive_add(cs.namespace(|| "B ayx"), &a.y, &a.x)?;
    let byx = naive_add(cs.namespace(|| "B byx"), &b.y, &b.x)?;
    ayx.mul(cs.namespace(|| "B"), &byx)?
  };

  #[allow(non_snake_case)]
  let C = {
    let D = AllocatedNum::alloc(cs.namespace(|| "Edwards D"), || Ok(EDWARDS_D))?;
    let aT2 = naive_add(cs.namespace(|| "2 aT"), &a.t, &a.t)?;
    let dbT = D.mul(cs.namespace(|| "D bT"), &b.t)?;
    aT2.mul(cs.namespace(|| "C"), &dbT)?
  };

  #[allow(non_snake_case)]
  let D = {
    let aZ2 = naive_add(cs.namespace(|| "2 aZ"), &a.z, &a.z)?;
    aZ2.mul(cs.namespace(|| "D"), &b.z)?
  };

  #[allow(non_snake_case)]
  let E = naive_sub(cs.namespace(|| "E"), &B, &A)?;
  #[allow(non_snake_case)]
  let F = naive_sub(cs.namespace(|| "F"), &D, &C)?;
  #[allow(non_snake_case)]
  let G = naive_add(cs.namespace(|| "G"), &D, &C)?;
  #[allow(non_snake_case)]
  let H = naive_add(cs.namespace(|| "H"), &B, &A)?;

  Ok(PrivatePoint {
    x: E.mul(cs.namespace(|| "x"), &F)?,
    y: G.mul(cs.namespace(|| "y"), &H)?,
    t: E.mul(cs.namespace(|| "t"), &H)?,
    z: F.mul(cs.namespace(|| "z"), &G)?,
  })
}
