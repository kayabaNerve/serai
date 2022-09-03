use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

pub use monero_serai::ringct::{RctPrunable, raw_hash_to_point, hash_to_point, generate_key_image, clsag, bulletproofs};

use crate::{Protocol, serialize::*};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctBase {
  pub fee: u64,
  pub ecdh_info: Vec<[u8; 8]>,
  pub commitments: Vec<EdwardsPoint>,
  pub mask_sums: [Scalar; 2],
}

impl RctBase {
  pub(crate) fn fee_weight(outputs: usize) -> usize {
    1 + 8 + (outputs * (8 + 32)) + (32 + 32)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W, rct_type: u8) -> std::io::Result<()> {
    w.write_all(&[rct_type])?;
    match rct_type {
      0 => Ok(()),
      7 => {
        write_varint(&self.fee, w)?;
        for ecdh in &self.ecdh_info {
          w.write_all(ecdh)?;
        }
        write_raw_vec(write_point, &self.commitments, w)?;
        write_raw_vec(write_scalar, &self.mask_sums, w)
      }
      _ => panic!("Serializing unknown RctType's Base"),
    }
  }

  pub fn deserialize<R: std::io::Read>(
    outputs: usize,
    r: &mut R,
  ) -> std::io::Result<(RctBase, u8)> {
    let rct_type = read_byte(r)?;
    Ok((
      if rct_type == 0 {
        RctBase { fee: 0, ecdh_info: vec![], commitments: vec![], mask_sums: [Scalar::zero(), Scalar::zero()], }
      } else {
        RctBase {
          fee: read_varint(r)?,
          ecdh_info: (0 .. outputs).map(|_| read_bytes(r)).collect::<Result<_, _>>()?,
          commitments: read_raw_vec(read_point, outputs, r)?,
          mask_sums: [read_scalar(r)?, read_scalar(r)?],
        }
      },
      rct_type,
    ))
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RctSignatures {
  pub base: RctBase,
  pub prunable: RctPrunable,
}

impl RctSignatures {
  pub(crate) fn fee_weight(protocol: Protocol, inputs: usize, outputs: usize) -> usize {
    RctBase::fee_weight(outputs) + RctPrunable::fee_weight(protocol.monero(), inputs, outputs)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.base.serialize(w, self.prunable.rct_type())?;
    self.prunable.serialize(w)
  }

  pub fn deserialize<R: std::io::Read>(
    decoys: Vec<usize>,
    outputs: usize,
    r: &mut R,
  ) -> std::io::Result<RctSignatures> {
    let base = RctBase::deserialize(outputs, r)?;
    Ok(RctSignatures { base: base.0, prunable: RctPrunable::deserialize(base.1, &decoys, r)? })
  }
}
