use rand_core::OsRng;

use ff::Field;
use multiexp::BatchVerifier;
use minimal_proof25519::{scalar::Scalar};

use bulletproofs::{Commitment, BulletproofsPlus};

#[test]
fn bulletproofs_plus() {
  // Create Bulletproofs for all possible output quantities
  let mut verifier = BatchVerifier::new(16);
  for i in 1 .. 17 {
    let commitments = (1 ..= i)
      .map(|i| Commitment::new(Scalar::random(&mut OsRng), u64::try_from(i).unwrap()))
      .collect::<Vec<_>>();

    let bp = BulletproofsPlus::prove(&mut OsRng, &commitments);

    let commitments = commitments.iter().map(Commitment::calculate).collect::<Vec<_>>();
    assert!(bp.verify(&mut OsRng, &commitments));
    assert!(bp.batch_verify(&mut OsRng, &mut verifier, i, &commitments));
  }
  assert!(verifier.verify_vartime());
}
