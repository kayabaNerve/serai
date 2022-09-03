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
  v19,
}

impl Protocol {
  pub fn ring_len(&self) -> usize {
    match self {
      Protocol::Unsupported => panic!("Unsupported protocol version"),
      Protocol::v19 => 11,
    }
  }

  pub fn monero(&self) -> monero_serai::Protocol {
    match self {
      Protocol::Unsupported => panic!("Unsupported protocol version"),
      Protocol::v19 => monero_serai::Protocol::v14,
    }
  }
}

lazy_static! {
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&H);
}

pub use monero_serai::{Commitment, random_scalar, hash, hash_to_scalar};
