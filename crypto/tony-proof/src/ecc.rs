use ff::{Field, PrimeFieldBits};
use group::Group;
use dalek_ff_group::{EDWARDS_D, EdwardsPoint};
use minimal_proof25519::scalar::Scalar;

use bellman::{
  SynthesisError, ConstraintSystem, Namespace,
  gadgets::{boolean::Boolean, num::AllocatedNum},
};

use crate::math::{constant_num, input_num, naive_add, naive_sub};

#[derive(Clone, Copy)]
pub(crate) struct Point {
  pub(crate) x: Scalar,
  pub(crate) y: Scalar,
}

impl Point {
  pub(crate) fn from(point: EdwardsPoint) -> Point {
    let (x, y) = point.decompose();
    Point { x, y }
  }
}

#[derive(Clone)]
pub(crate) struct PrivatePoint {
  pub(crate) x: AllocatedNum<Scalar>,
  pub(crate) y: AllocatedNum<Scalar>,
  pub(crate) z: AllocatedNum<Scalar>,
  pub(crate) t: AllocatedNum<Scalar>,
}

impl PrivatePoint {
  #[cfg(test)]
  pub(crate) fn identity<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
  ) -> Result<PrivatePoint, SynthesisError> {
    Ok(PrivatePoint {
      x: constant_num(cs.namespace(|| "x"), Scalar::zero())?,
      y: constant_num(cs.namespace(|| "y"), Scalar::one())?,
      z: constant_num(cs.namespace(|| "z"), Scalar::one())?,
      t: constant_num(cs.namespace(|| "t"), Scalar::zero())?,
    })
  }

  pub(crate) fn from<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: Point,
  ) -> Result<PrivatePoint, SynthesisError> {
    Ok(PrivatePoint {
      x: input_num(cs.namespace(|| "x"), point.x)?,
      y: input_num(cs.namespace(|| "y"), point.y)?,
      z: constant_num(cs.namespace(|| "z"), Scalar::one())?,
      t: input_num(cs.namespace(|| "t"), point.x * point.y)?,
    })
  }

  pub(crate) fn from_edwards<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    point: EdwardsPoint,
  ) -> Result<PrivatePoint, SynthesisError> {
    PrivatePoint::from(cs, Point::from(point))
  }
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
    // TODO: Allocate this once, not per addition
    let D = constant_num(cs.namespace(|| "Edwards D"), EDWARDS_D)?;
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

// TODO: Can this be windowed?
// It's doing 2 * 253 = 506 additions. With a 2^4 window, it's 16 + 253 + (253 / 16) = 285
pub(crate) fn edwards_basepoint_mul<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  start: PrivatePoint,
  scalar: AllocatedNum<Scalar>,
) -> Result<PrivatePoint, SynthesisError> {
  let to_private = |mut cs: Namespace<'_, _, _>, point: EdwardsPoint| {
    let (x, y) = point.decompose();
    Ok::<_, SynthesisError>(PrivatePoint {
      x: constant_num(cs.namespace(|| "x"), x)?,
      y: constant_num(cs.namespace(|| "y"), y)?,
      z: constant_num(cs.namespace(|| "z"), Scalar::one())?,
      t: constant_num(cs.namespace(|| "t"), x * y)?,
    })
  };

  let select = |mut cs: Namespace<'_, _, _>, point: PrivatePoint, bit: &Boolean| {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
        point.x.get_value().ok_or(SynthesisError::AssignmentMissing)?
      } else {
        Scalar::zero()
      })
    })?;
    cs.enforce(
      || "selected x",
      |lc| lc + point.x.get_variable(),
      |_| bit.lc(CS::one(), Scalar::one()),
      |lc| lc + x.get_variable(),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
        point.y.get_value().ok_or(SynthesisError::AssignmentMissing)?
      } else {
        Scalar::one()
      })
    })?;
    // TODO: Does this hold? It *should*
    cs.enforce(
      || "selected y",
      |lc| lc + point.y.get_variable() - CS::one(),
      |_| bit.lc(CS::one(), Scalar::one()),
      |lc| lc + y.get_variable() - CS::one(),
    );

    let z = AllocatedNum::alloc(cs.namespace(|| "z"), || {
      Ok(if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
        point.z.get_value().ok_or(SynthesisError::AssignmentMissing)?
      } else {
        Scalar::one()
      })
    })?;
    cs.enforce(
      || "selected z",
      |lc| lc + point.z.get_variable() - CS::one(),
      |_| bit.lc(CS::one(), Scalar::one()),
      |lc| lc + z.get_variable() - CS::one(),
    );

    let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
      Ok(if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
        point.t.get_value().ok_or(SynthesisError::AssignmentMissing)?
      } else {
        Scalar::zero()
      })
    })?;
    cs.enforce(
      || "selected t",
      |lc| lc + point.t.get_variable(),
      |_| bit.lc(CS::one(), Scalar::one()),
      |lc| lc + t.get_variable(),
    );

    Ok::<_, SynthesisError>(PrivatePoint { x, y, z, t })
  };

  let mut generator = EdwardsPoint::generator();
  // TODO: Can this generator not be made private?
  let mut private_generator = Some(to_private(cs.namespace(|| "generator 0"), generator)?);

  let mut sum = start;

  // There is a strict mode for this, ensuring the bits form a valid Scalar (Proof25519)
  // Since we're already using a subset of these bits, this would be pointless
  // While we could check the 253 bits we do use are within the actual Scalar field (Ed25519),
  // the following addition formula isn't affected
  let bits = scalar.to_bits_le(cs.namespace(|| "scalar bits"))?;
  for (i, bit) in bits.iter().take(253).enumerate() {
    let bit = select(
      cs.namespace(|| "bit value ".to_string() + &i.to_string()),
      private_generator.take().unwrap(),
      bit,
    )?;
    sum = edwards_add(cs.namespace(|| "addition ".to_string() + &i.to_string()), sum, bit)?;
    if i != 252 {
      generator = generator.double();
      private_generator = Some(to_private(
        cs.namespace(|| "generator ".to_string() + &(i + 1).to_string()),
        generator,
      )?);
    }
  }

  Ok(sum)
}

pub(crate) fn invert<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  value: AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let mut res = constant_num(cs.namespace(|| "inverse"), Scalar::one())?;
  for (i, bit) in (-Scalar::from(2u8)).to_le_bits().iter().rev().enumerate() {
    res = res.mul(cs.namespace(|| "square ".to_string() + &i.to_string()), &res)?;
    if *bit {
      res = res.mul(cs.namespace(|| "multiplication ".to_string() + &i.to_string()), &value)?;
    }
  }
  Ok(res)
}
