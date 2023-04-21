use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::edwards::EdwardsPoint;

/// Decoy data, containing the actual member as well (at index `i`).
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Decoys {
  pub i: u8,
  pub offsets: Vec<u64>,
  pub ring: Vec<[EdwardsPoint; 2]>,
}

impl Decoys {
  pub fn len(&self) -> usize {
    self.offsets.len()
  }
}
