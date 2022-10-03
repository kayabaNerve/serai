use minimal_proof25519::scalar::Scalar;

use bellman::{
  SynthesisError, ConstraintSystem,
  gadgets::{Assignment, num::AllocatedNum},
};

pub(crate) fn constant_num<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  value: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let num = AllocatedNum::alloc(cs.namespace(|| "number"), || Ok(value))?;
  cs.enforce(
    || "constant",
    |lc| lc + num.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + (value, CS::one()),
  );
  Ok(num)
}

// TODO: Can we use AllocatedNum::inputize for this?
pub(crate) fn input_num<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  value: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let num = AllocatedNum::alloc(cs.namespace(|| "number"), || Ok(value))?;
  cs.enforce(
    || "variable",
    |lc| lc + num.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + (value, CS::one()),
  );
  Ok(num)
}

// Naive as it doesn't merge this constraint with any other, which may be possible?
pub(crate) fn naive_add<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &AllocatedNum<Scalar>,
  b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let sum = AllocatedNum::alloc(cs.namespace(|| "allocation"), || {
    Ok(*a.get_value().get()? + b.get_value().get()?)
  })?;
  cs.enforce(
    || "calculation",
    |lc| lc + a.get_variable() + b.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + sum.get_variable(),
  );
  Ok(sum)
}

pub(crate) fn naive_sub<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &AllocatedNum<Scalar>,
  b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let sum = AllocatedNum::alloc(cs.namespace(|| "allocation"), || {
    Ok(*a.get_value().get()? - b.get_value().get()?)
  })?;
  cs.enforce(
    || "calculation",
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + sum.get_variable(),
  );
  Ok(sum)
}
