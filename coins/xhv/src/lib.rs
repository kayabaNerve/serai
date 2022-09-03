use lazy_static::lazy_static;

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsBasepointTable;

pub use monero_generators::H;

#[cfg(feature = "multisig")]
pub mod frost;

mod serialize;

pub mod ringct;

pub mod transaction;
pub mod block;

pub mod rpc;
pub mod wallet;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
#[allow(non_camel_case_types)]
pub enum Protocol {
  Unsupported,
  v14,
  v16,
}

impl Protocol {
  pub fn ring_len(&self) -> usize {
    match self {
      Protocol::Unsupported => panic!("Unsupported protocol version"),
      Protocol::v14 => 11,
      Protocol::v16 => 16,
    }
  }

  pub fn bp_plus(&self) -> bool {
    match self {
      Protocol::Unsupported => panic!("Unsupported protocol version"),
      Protocol::v14 => false,
      Protocol::v16 => true,
    }
  }
}

lazy_static! {
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&H);
}

pub use monero_serai::{Commitment, random_scalar, hash, hash_to_scalar};
