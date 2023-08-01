use std::{str::FromStr, collections::HashMap};

use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::Secp256k1;
use frost::{*, sign::*};

use bitcoin_serai::{
  bitcoin::{
    consensus::Encodable,
    network::constants::Network,
    address::{NetworkUnchecked, Address},
  },
  wallet::*,
};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use crate::*;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PortableOutput<'a> {
  hash: [u8; 32],
  vout: u32,
  value: u64,
  script_pubkey: &'a [u8],
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OwnedPortableOutput {
  hash: [u8; 32],
  vout: u32,
  value: u64,
  script_pubkey: Vec<u8>,
}

impl OwnedPortableOutput {
  #[no_mangle]
  pub extern "C" fn hash(&self) -> *const u8 {
    self.hash.as_ptr()
  }
  #[no_mangle]
  pub extern "C" fn vout(&self) -> u32 {
    self.vout
  }
  #[no_mangle]
  pub extern "C" fn value(&self) -> u64 {
    self.value
  }
  #[no_mangle]
  pub extern "C" fn script_pubkey(&self) -> *const u8 {
    self.script_pubkey.as_ptr()
  }
}

impl TryInto<ReceivedOutput> for OwnedPortableOutput {
  type Error = ();
  fn try_into(self) -> Result<ReceivedOutput, ()> {
    let mut buf = vec![0; 32];
    buf.extend(&self.value.to_le_bytes());
    buf.push(u8::try_from(self.script_pubkey.len()).map_err(|_| ())?);
    buf.extend(self.script_pubkey);
    for i in (0 .. 32).rev() {
      buf.push(self.hash[i]);
    }
    buf.extend(&self.vout.to_le_bytes());
    ReceivedOutput::read(&mut buf.as_slice()).map_err(|_| ())
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignConfig {
  network: Network,
  inputs: Vec<Box<OwnedPortableOutput>>,
  payments: Vec<(String, u64)>,
  change: String,
  fee_per_weight: u64,
}

impl SignConfig {
  #[no_mangle]
  pub extern "C" fn inputs(&self) -> usize {
    self.inputs.len()
  }
  #[allow(clippy::borrowed_box)]
  #[no_mangle]
  pub extern "C" fn input(&self, i: usize) -> &Box<OwnedPortableOutput> {
    &self.inputs[i]
  }
  #[no_mangle]
  pub extern "C" fn payments(&self) -> &[(String, u64)] {
    &self.payments
  }
  #[no_mangle]
  pub extern "C" fn change(&self) -> StringView {
    StringView::new(&self.change)
  }
  #[no_mangle]
  pub extern "C" fn fee_per_weight(&self) -> u64 {
    self.fee_per_weight
  }
}

fn sign_config_to_tx(network: Network, config: &SignConfig) -> Result<SignableTransaction, u16> {
  SignableTransaction::new(
    config
      .inputs
      .iter()
      .cloned()
      .map(|input| (*input).try_into())
      .collect::<Result<_, _>>()
      .map_err(|_| INVALID_OUTPUT_ERROR)?,
    &config
      .payments
      .iter()
      .map(|(address, amount)| {
        Ok((
          Address::<NetworkUnchecked>::from_str(address)
            .map_err(|_| INVALID_ADDRESS_ERROR)?
            .require_network(network)
            .map_err(|_| INVALID_NETWORK_ERROR)?,
          *amount,
        ))
      })
      .collect::<Result<Vec<_>, u16>>()?,
    Some(
      Address::<NetworkUnchecked>::from_str(&config.change)
        .map_err(|_| INVALID_ADDRESS_ERROR)?
        .require_network(network)
        .map_err(|_| INVALID_NETWORK_ERROR)?,
    ),
    None,
    config.fee_per_weight,
  )
  .map_err(|e| match e {
    TransactionError::NoInputs => NO_INPUTS_ERROR,
    TransactionError::NoOutputs => NO_OUTPUTS_ERROR,
    TransactionError::DustPayment => DUST_ERROR,
    TransactionError::TooMuchData => unreachable!(),
    TransactionError::NotEnoughFunds => NOT_ENOUGH_FUNDS_ERROR,
    TransactionError::TooLargeTransaction => TOO_LARGE_TRANSACTION_ERROR,
  })
}

#[no_mangle]
pub extern "C" fn new_sign_config(
  network: Network,
  outputs: &[PortableOutput],
  payments: &[(&str, u64)],
  change: StringView,
  fee_per_weight: u64,
) -> Result<(SignConfig, OwnedString), u16> {
  let config = SignConfig {
    network,
    inputs: outputs
      .iter()
      .map(|output| {
        Box::new(OwnedPortableOutput {
          hash: output.hash,
          vout: output.vout,
          value: output.value,
          script_pubkey: output.script_pubkey.to_vec(),
        })
      })
      .collect(),
    payments: payments.iter().map(|(address, amount)| (address.to_string(), *amount)).collect(),
    change: change.to_string().ok_or(INVALID_ADDRESS_ERROR)?,
    fee_per_weight,
  };

  sign_config_to_tx(network, &config)?;

  let res = Base64::encode_string(&bincode::serialize(&config).unwrap());
  Ok((config, OwnedString::new(res)))
}

#[no_mangle]
pub extern "C" fn decode_sign_config(
  network: Network,
  encoded: StringView,
) -> Result<SignConfig, u16> {
  let decoded = bincode::deserialize::<SignConfig>(
    &Base64::decode_vec(&encoded.to_string().ok_or(INVALID_ENCODING_ERROR)?)
      .map_err(|_| INVALID_ENCODING_ERROR)?,
  )
  .map_err(|_| INVALID_ENCODING_ERROR)?;
  if decoded.network != network {
    Err(INVALID_NETWORK_ERROR)?;
  }
  sign_config_to_tx(network, &decoded)?;
  Ok(decoded)
}

#[no_mangle]
pub extern "C" fn attempt_sign(
  keys: ThresholdKeys<Secp256k1>,
  config: &SignConfig,
) -> Result<(Box<TransactionSignMachine>, OwnedString), u16> {
  let (machine, preprocesses) = sign_config_to_tx(config.network, config)
    .expect("created a SignConfig which couldn't create a TX")
    .multisig(keys, RecommendedTranscript::new(b"HRF Sign Transaction"))
    .ok_or(WRONG_KEYS_ERROR)?
    .preprocess(&mut OsRng);
  Ok((machine.into(), OwnedString::new(Base64::encode_string(&preprocesses.serialize()))))
}

#[no_mangle]
pub unsafe extern "C" fn continue_sign(
  machine: Box<TransactionSignMachine>,
  preprocesses: *const StringView,
  preprocesses_len: usize,
) -> Result<(Box<TransactionSignatureMachine>, OwnedString), u16> {
  let preprocesses = unsafe { std::slice::from_raw_parts(preprocesses, preprocesses_len) };

  let mut map = HashMap::new();
  for (i, preprocess) in preprocesses.iter().enumerate() {
    map.insert(
      Participant::new(u16::try_from(i + 1).map_err(|_| INVALID_PARTICIPANT_ERROR)?).unwrap(),
      machine
        .read_preprocess(
          &mut Base64::decode_vec(&preprocess.to_string().ok_or(INVALID_ENCODING_ERROR)?)
            .map_err(|_| INVALID_ENCODING_ERROR)?
            .as_slice(),
        )
        .map_err(|_| INVALID_ENCODING_ERROR)?,
    );
  }
  let (machine, share) = machine.sign(map, &[]).map_err(|_| INVALID_PREPROCESS_ERROR)?;
  Ok((machine.into(), OwnedString::new(Base64::encode_string(&share.serialize()))))
}

#[no_mangle]
pub unsafe extern "C" fn complete_sign(
  machine: Box<TransactionSignatureMachine>,
  shares: *const StringView,
  shares_len: usize,
) -> Result<Vec<u8>, u16> {
  let shares = unsafe { std::slice::from_raw_parts(shares, shares_len) };
  let mut map = HashMap::new();
  for (i, share) in shares.iter().enumerate() {
    map.insert(
      Participant::new(u16::try_from(i + 1).map_err(|_| INVALID_PARTICIPANT_ERROR)?).unwrap(),
      machine
        .read_share(
          &mut Base64::decode_vec(&share.to_string().ok_or(INVALID_ENCODING_ERROR)?)
            .map_err(|_| INVALID_ENCODING_ERROR)?
            .as_slice(),
        )
        .map_err(|_| INVALID_ENCODING_ERROR)?,
    );
  }
  let tx = machine.complete(map).map_err(|_| INVALID_SHARE_ERROR)?;
  let mut buf = Vec::with_capacity(1024);
  tx.consensus_encode(&mut buf).unwrap();
  Ok(buf)
}
