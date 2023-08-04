use std::{str::FromStr, collections::HashMap};

use rand_core::OsRng;

use transcript::{Transcript, RecommendedTranscript};
use frost::{*, sign::*};

use bitcoin_serai::{
  bitcoin::{
    consensus::Encodable,
    network::constants::Network as BNetwork,
    address::{NetworkUnchecked, Address},
  },
  wallet::*,
};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use crate::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
  Mainnet,
  Testnet,
  Regtest,
}

impl Network {
  fn to_bitcoin(self) -> BNetwork {
    match self {
      Self::Mainnet => BNetwork::Bitcoin,
      Self::Testnet => BNetwork::Testnet,
      Self::Regtest => BNetwork::Regtest,
    }
  }
}

#[no_mangle]
pub unsafe extern "C" fn address_for_keys(
  network: Network,
  keys: &ThresholdKeysWrapper,
) -> OwnedString {
  OwnedString::new(
    address(network.to_bitcoin(), tweak_keys(&keys.0).group_key())
      .expect("tweaked keys didn't have an address")
      .to_string(),
  )
}

#[no_mangle]
pub unsafe extern "C" fn script_pub_key_for_keys(keys: &ThresholdKeysWrapper) -> OwnedString {
  OwnedString::new(hex::encode(
    address(BNetwork::Bitcoin, tweak_keys(&keys.0).group_key())
      .expect("tweaked keys didn't have an address")
      .script_pubkey(),
  ))
}

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PortableOutput {
  pub hash: [u8; 32],
  pub vout: u32,
  pub value: u64,
  pub script_pubkey: *const u8,
  pub script_pubkey_len: usize,
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
  pub extern "C" fn output_hash(&self) -> *const u8 {
    self.hash.as_ptr()
  }
  #[no_mangle]
  pub extern "C" fn output_vout(&self) -> u32 {
    self.vout
  }
  #[no_mangle]
  pub extern "C" fn output_value(&self) -> u64 {
    self.value
  }
  #[no_mangle]
  pub extern "C" fn output_script_pubkey_len(&self) -> usize {
    self.script_pubkey.len()
  }
  #[no_mangle]
  pub extern "C" fn output_script_pubkey(&self) -> *const u8 {
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
  network: BNetwork,
  #[allow(clippy::vec_box)]
  inputs: Vec<Box<OwnedPortableOutput>>,
  payments: Vec<(String, u64)>,
  change: String,
  fee_per_weight: u64,
}

impl SignConfig {
  #[no_mangle]
  pub extern "C" fn sign_inputs(&self) -> usize {
    self.inputs.len()
  }
  #[allow(clippy::borrowed_box)]
  #[no_mangle]
  pub extern "C" fn sign_input(&self, i: usize) -> &Box<OwnedPortableOutput> {
    &self.inputs[i]
  }
  #[no_mangle]
  pub extern "C" fn sign_payments(&self) -> usize {
    self.payments.len()
  }
  #[no_mangle]
  pub extern "C" fn sign_payment_address(&self, i: usize) -> StringView {
    StringView::new(&self.payments[i].0)
  }
  #[no_mangle]
  pub extern "C" fn sign_payment_amount(&self, i: usize) -> u64 {
    self.payments[i].1
  }
  #[no_mangle]
  pub extern "C" fn sign_change(&self) -> StringView {
    StringView::new(&self.change)
  }
  #[no_mangle]
  pub extern "C" fn sign_fee_per_weight(&self) -> u64 {
    self.fee_per_weight
  }
}

fn sign_config_to_tx(network: BNetwork, config: &SignConfig) -> Result<SignableTransaction, u16> {
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

#[repr(C)]
pub struct SignConfigRes {
  config: Box<SignConfig>,
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn new_sign_config(
  network: Network,
  outputs: *const PortableOutput,
  outputs_len: usize,
  payments: usize,
  payment_addresses: *const StringView,
  payment_amounts: *const u64,
  change: StringView,
  fee_per_weight: u64,
) -> CResult<SignConfigRes> {
  CResult::new(new_sign_config_rust(
    network,
    unsafe { std::slice::from_raw_parts(outputs, outputs_len) },
    unsafe { std::slice::from_raw_parts(payment_addresses, payments) },
    unsafe { std::slice::from_raw_parts(payment_amounts, payments) },
    change,
    fee_per_weight,
  ))
}

fn new_sign_config_rust(
  network: Network,
  outputs: &[PortableOutput],
  payment_addresses: &[StringView],
  payment_amounts: &[u64],
  change: StringView,
  fee_per_weight: u64,
) -> Result<SignConfigRes, u16> {
  let network = network.to_bitcoin();
  let config = SignConfig {
    network,
    inputs: outputs
      .iter()
      .map(|output| {
        Box::new(OwnedPortableOutput {
          hash: output.hash,
          vout: output.vout,
          value: output.value,
          script_pubkey: (unsafe {
            std::slice::from_raw_parts(output.script_pubkey, output.script_pubkey_len)
          })
          .to_vec(),
        })
      })
      .collect(),
    payments: payment_addresses
      .iter()
      .zip(payment_amounts)
      .map(|(address, amount)| {
        address.to_string().ok_or(INVALID_ADDRESS_ERROR).map(|address| (address, *amount))
      })
      .collect::<Result<_, _>>()?,
    change: change.to_string().ok_or(INVALID_ADDRESS_ERROR)?,
    fee_per_weight,
  };

  sign_config_to_tx(network, &config)?;

  let res = Base64::encode_string(&bincode::serialize(&config).unwrap());
  Ok(SignConfigRes { config: config.into(), encoded: OwnedString::new(res) })
}

#[no_mangle]
pub extern "C" fn decode_sign_config(network: Network, encoded: StringView) -> CResult<SignConfig> {
  CResult::new(decode_sign_config_rust(network, encoded))
}

fn decode_sign_config_rust(network: Network, encoded: StringView) -> Result<SignConfig, u16> {
  let network = network.to_bitcoin();
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

pub struct TransactionSignMachineWrapper(TransactionSignMachine);
pub struct TransactionSignatureMachineWrapper(TransactionSignatureMachine);

#[repr(C)]
pub struct AttemptSignRes {
  machine: Box<TransactionSignMachineWrapper>,
  preprocess: OwnedString,
}

#[no_mangle]
pub extern "C" fn attempt_sign(
  keys: &ThresholdKeysWrapper,
  config: &SignConfig,
) -> CResult<AttemptSignRes> {
  CResult::new(attempt_sign_rust(keys, config))
}

fn attempt_sign_rust(
  keys: &ThresholdKeysWrapper,
  config: &SignConfig,
) -> Result<AttemptSignRes, u16> {
  let (machine, preprocesses) = sign_config_to_tx(config.network, config)
    .expect("created a SignConfig which couldn't create a TX")
    .multisig(tweak_keys(&keys.0), RecommendedTranscript::new(b"HRF Sign Transaction"))
    .ok_or(WRONG_KEYS_ERROR)?
    .preprocess(&mut OsRng);
  Ok(AttemptSignRes {
    machine: TransactionSignMachineWrapper(machine).into(),
    preprocess: OwnedString::new(Base64::encode_string(&preprocesses.serialize())),
  })
}

#[repr(C)]
pub struct ContinueSignRes {
  machine: Box<TransactionSignatureMachineWrapper>,
  preprocess: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn continue_sign(
  machine: Box<TransactionSignMachineWrapper>,
  preprocesses: *const StringView,
  preprocesses_len: usize,
) -> CResult<ContinueSignRes> {
  CResult::new(continue_sign_rust(machine, preprocesses, preprocesses_len))
}

fn continue_sign_rust(
  machine: Box<TransactionSignMachineWrapper>,
  preprocesses: *const StringView,
  preprocesses_len: usize,
) -> Result<ContinueSignRes, u16> {
  let preprocesses = unsafe { std::slice::from_raw_parts(preprocesses, preprocesses_len) };

  let mut map = HashMap::new();
  for (i, preprocess) in preprocesses.iter().enumerate() {
    map.insert(
      Participant::new(u16::try_from(i + 1).map_err(|_| INVALID_PARTICIPANT_ERROR)?).unwrap(),
      machine
        .0
        .read_preprocess(
          &mut Base64::decode_vec(&preprocess.to_string().ok_or(INVALID_ENCODING_ERROR)?)
            .map_err(|_| INVALID_ENCODING_ERROR)?
            .as_slice(),
        )
        .map_err(|_| INVALID_ENCODING_ERROR)?,
    );
  }
  let (machine, share) = machine.0.sign(map, &[]).map_err(|_| INVALID_PREPROCESS_ERROR)?;
  Ok(ContinueSignRes {
    machine: TransactionSignatureMachineWrapper(machine).into(),
    preprocess: OwnedString::new(Base64::encode_string(&share.serialize())),
  })
}

#[no_mangle]
pub unsafe extern "C" fn complete_sign(
  machine: Box<TransactionSignatureMachineWrapper>,
  shares: *const StringView,
  shares_len: usize,
) -> CResult<OwnedString> {
  CResult::new(complete_sign_rust(machine, unsafe {
    std::slice::from_raw_parts(shares, shares_len)
  }))
}

fn complete_sign_rust(
  machine: Box<TransactionSignatureMachineWrapper>,
  shares: &[StringView],
) -> Result<OwnedString, u16> {
  let mut map = HashMap::new();
  for (i, share) in shares.iter().enumerate() {
    map.insert(
      Participant::new(u16::try_from(i + 1).map_err(|_| INVALID_PARTICIPANT_ERROR)?).unwrap(),
      machine
        .0
        .read_share(
          &mut Base64::decode_vec(&share.to_string().ok_or(INVALID_ENCODING_ERROR)?)
            .map_err(|_| INVALID_ENCODING_ERROR)?
            .as_slice(),
        )
        .map_err(|_| INVALID_ENCODING_ERROR)?,
    );
  }
  let tx = machine.0.complete(map).map_err(|_| INVALID_SHARE_ERROR)?;
  let mut buf = Vec::with_capacity(1024);
  tx.consensus_encode(&mut buf).unwrap();
  Ok(OwnedString::new(hex::encode(buf)))
}
