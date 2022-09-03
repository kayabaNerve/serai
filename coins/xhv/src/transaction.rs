use core::cmp::Ordering;

use zeroize::Zeroize;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use crate::{
  Protocol, hash,
  serialize::*,
  ringct::{RctPrunable, RctSignatures},
};

pub use monero_serai::transaction::Timelock;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  Gen(u64),
  ToKey { asset: Asset, amount: u64, key_offsets: Vec<u64>, key_image: EdwardsPoint },
}

impl Input {
  // Worst-case predictive len
  pub fn fee_weight(ring_len: usize) -> usize {
    // Uses 1 byte for the VarInt amount due to amount being 0
    // Uses 1 byte for the VarInt encoding of the length of the ring as well
    1 + 5 + 1 + 1 + (8 * ring_len) + 32
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    match self {
      Input::Gen(height) => {
        w.write_all(&[255])?;
        write_varint(height, w)
      }

      Input::ToKey { amount, key_offsets, key_image } => {
        w.write_all(&[2 + (0 if xhv, 1 or 2? if usd, 3 if xasset)])?;
        write_varint(amount, w)?;
        write_vec(write_varint, key_offsets, w)?;
        write_point(key_image, w)
      }
    }
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Input> {
    Ok(match read_byte(r)? {
      255 => Input::Gen(read_varint(r)?),
      2 => Input::ToKey {
        amount: read_varint(r)?,
        key_offsets: read_vec(read_varint, r)?,
        key_image: read_torsion_free_point(r)?,
      },
      _ => Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Tried to deserialize unknown/unused input type",
      ))?,
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Asset {
  Xhv,
  XUsd,
  XAsset(string),
}

// Doesn't bother moving to an enum for the unused Script classes
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  pub asset: Asset,
  pub amount: u64,
  pub key: CompressedEdwardsY,
  pub timelock: Timelock,
}

impl Output {
  pub fn fee_weight() -> usize {
    1 + 5 + 1 + 32 + 8
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.amount, w)?;
    w.write_all(&[2 + (if matches!(self.asset, Asset::Xhv) { 0 } else if matches!(self.asset, Asset::XUsd) { 1 } else { 2 })])?;
    w.write_all(&self.key.to_bytes())?;
    if let Asset::XAsset(asset) = self.asset {
      w.write_vec(write_byte, asset.as_bytes(), w)?;
    }
    Ok(())
  }

  pub(crate) fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Output> {
    let amount = read_varint(r)?;
    let asset = read_byte(r)?;
    let key = CompressedEdwardsY(read_bytes(r)?);
    Ok(Output {
      asset: match asset {
        2 => Asset::Xhv,
        3 => Asset::XUsd,
        4 => Asset::XAsset(read_vec(read_byte(r)?, r))
      },
      amount,
      key,
      timelock: Timelock::from_raw(u64::MAX) // Stub value since this isn't actually present here
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionPrefix {
  pub version: u64,
  pub inputs: Vec<Input>,
  pub outputs: Vec<Output>,
  pub extra: Vec<u8>,

  pub pricing_record: u64,
  pub burnt: u64,
  pub minted: u64,
}

impl TransactionPrefix {
  pub(crate) fn fee_weight(ring_len: usize, inputs: usize, outputs: usize, extra: usize) -> usize {
    // Assumes Timelock::None since this library won't let you create a TX with a timelock
    1 + 1 +
      varint_len(inputs) +
      (inputs * Input::fee_weight(ring_len)) +
      1 +
      (outputs * Output::fee_weight()) +
      varint_len(extra) +
      extra +
      8 + 8 + 8
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.version, w)?;
    write_vec(Input::serialize, &self.inputs, w)?;
    write_vec(Output::serialize, &self.outputs, w)?;
    write_varint(&self.extra.len().try_into().unwrap(), w)?;
    w.write_all(&self.extra)

    write_varint(&self.pricing_record, w)?;
    write_varint(&self.outputs.len().try_into().unwrap(), w)?;
    for output in self.outputs {
      output.timelock.serialize(w)?;
    }
    write_varint(&self.burnt, w)?;
    write_varint(&self.minted, w)?;
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<TransactionPrefix> {
    let mut prefix = TransactionPrefix {
      version: read_varint(r)?,
      inputs: read_vec(Input::deserialize, r)?,
      outputs: read_vec(Output::deserialize, r)?,
      extra: read_vec(read_byte, r)?,

      pricing_record: read_varint(r)?,
      burnt: 0,
      minted: 0,
    };

    if read_varint(r)? != prefix.outputs.len().try_into().unwrap() {
      Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Incorrect amount of timelocks",
      ))?
    }
    for output in prefix.outputs.iter_mut() {
      output.timelock = Timelock::from_raw(read_varint(r)?);
    }

    prefix.burnt = read_varint(r)?;
    prefix.minted = read_varint(r)?;
    Ok(prefix)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
  pub prefix: TransactionPrefix,
  pub rct_signatures: RctSignatures,
}

impl Transaction {
  pub(crate) fn fee_weight(
    protocol: Protocol,
    inputs: usize,
    outputs: usize,
    extra: usize,
  ) -> usize {
    TransactionPrefix::fee_weight(protocol.ring_len(), inputs, outputs, extra) +
      RctSignatures::fee_weight(protocol, inputs, outputs)
  }

  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.prefix.serialize(w)?;
    self.rct_signatures.serialize(w)
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Transaction> {
    let prefix = TransactionPrefix::deserialize(r)?;
    Ok(Transaction {
      rct_signatures: RctSignatures::deserialize(
        prefix
          .inputs
          .iter()
          .map(|input| match input {
            Input::Gen(_) => 0,
            Input::ToKey { key_offsets, .. } => key_offsets.len(),
          })
          .collect(),
        prefix.outputs.len(),
        r,
      )?,
      prefix,
    })
  }

  pub fn hash(&self) -> [u8; 32] {
    let mut serialized = Vec::with_capacity(2048);
    if self.prefix.version == 1 {
      self.serialize(&mut serialized).unwrap();
      hash(&serialized)
    } else {
      let mut sig_hash = Vec::with_capacity(96);

      self.prefix.serialize(&mut serialized).unwrap();
      sig_hash.extend(hash(&serialized));
      serialized.clear();

      self
        .rct_signatures
        .base
        .serialize(&mut serialized, self.rct_signatures.prunable.rct_type())
        .unwrap();
      sig_hash.extend(hash(&serialized));
      serialized.clear();

      match self.rct_signatures.prunable {
        RctPrunable::Null => serialized.resize(32, 0),
        _ => {
          self.rct_signatures.prunable.serialize(&mut serialized).unwrap();
          serialized = hash(&serialized).to_vec();
        }
      }
      sig_hash.extend(&serialized);

      hash(&sig_hash)
    }
  }

  pub fn signature_hash(&self) -> [u8; 32] {
    let mut serialized = Vec::with_capacity(2048);
    let mut sig_hash = Vec::with_capacity(96);

    self.prefix.serialize(&mut serialized).unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self
      .rct_signatures
      .base
      .serialize(&mut serialized, self.rct_signatures.prunable.rct_type())
      .unwrap();
    sig_hash.extend(hash(&serialized));
    serialized.clear();

    self.rct_signatures.prunable.signature_serialize(&mut serialized).unwrap();
    sig_hash.extend(&hash(&serialized));

    hash(&sig_hash)
  }
}
