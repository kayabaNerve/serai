use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{Ciphersuite, Secp256k1};
use ::frost::dkg::{*, encryption::*, resharing::*};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use crate::{*, key_gen::*};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResharerConfig {
  new_threshold: u16,
  resharers: Vec<u16>,
  new_participants: Vec<String>,
}

impl ResharerConfig {
  #[no_mangle]
  pub extern "C" fn resharer_new_threshold(&self) -> u16 {
    self.new_threshold
  }

  #[no_mangle]
  pub extern "C" fn resharer_resharers(&self) -> usize {
    self.resharers.len()
  }

  #[no_mangle]
  pub extern "C" fn resharer_resharer(&self, i: usize) -> u16 {
    self.resharers[i]
  }

  #[no_mangle]
  pub extern "C" fn resharer_new_participants(&self) -> usize {
    self.new_participants.len()
  }

  #[no_mangle]
  pub extern "C" fn resharer_new_participant(&self, i: usize) -> StringView {
    StringView::new(&self.new_participants[i])
  }
}

fn check_t_n(threshold: u16, participants: u16) -> Result<(), u16> {
  match ThresholdParams::new(threshold, participants, Participant::new(1).unwrap()) {
    Err(DkgError::ZeroParameter(..)) => Err(ZERO_PARAMETER_ERROR)?,
    Err(DkgError::InvalidThreshold(..)) => Err(INVALID_THRESHOLD_ERROR)?,
    Err(DkgError::InvalidParticipant(..)) => Err(INVALID_PARTICIPANT_ERROR)?,
    Err(_) => Err(UNKNOWN_ERROR)?,
    Ok(_) => Ok(()),
  }
}

#[repr(C)]
pub struct ResharerConfigRes {
  config: Box<ResharerConfig>,
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn new_resharer_config(
  new_threshold: u16,
  resharers: *const u16,
  resharers_len: u16,
  new_participants: *const StringView,
  new_participants_len: u16,
) -> CResult<ResharerConfigRes> {
  CResult::new(new_resharer_config_rust(
    new_threshold,
    resharers,
    resharers_len,
    new_participants,
    new_participants_len,
  ))
}

unsafe fn new_resharer_config_rust(
  new_threshold: u16,
  resharers_ptr: *const u16,
  resharers_len: u16,
  new_participants: *const StringView,
  new_participants_len: u16,
) -> Result<ResharerConfigRes, u16> {
  check_t_n(new_threshold, new_participants_len)?;
  if new_participants_len == u16::MAX { todo!(); }

  // if resharers_len < keys.params().t() { todo!(); } TODO
  let mut resharers = HashSet::new();
  for resharer in unsafe { std::slice::from_raw_parts(resharers_ptr, resharers_len.into()) } {
    let resharer = *resharer;
    if resharer == 0 { todo!(); }
    resharers.insert(resharer);
  }
  if resharers.len() != usize::from(resharers_len) { todo!(); }

  let mut resharers = resharers.into_iter().collect::<Vec<_>>();
  resharers.sort();

  let new_participants = unsafe { std::slice::from_raw_parts(new_participants, new_participants_len.into()) };
  let mut new_participants_res = vec![];
  for participant in new_participants {
    if participant.len == 0 {
      Err(INVALID_NAME_ERROR)?;
    }
    let Some(participant) = participant.to_string() else { Err(INVALID_NAME_ERROR)? };
    new_participants_res.push(participant);
  }

  let config = ResharerConfig { new_threshold, resharers, new_participants: new_participants_res };
  let encoded = OwnedString::new(Base64::encode_string(&bincode::serialize(&config).unwrap()));
  Ok(ResharerConfigRes { config: config.into(), encoded })
}

#[no_mangle]
pub extern "C" fn decode_resharer_config(config: StringView) -> CResult<Box<ResharerConfig>> {
  CResult::new(decode_resharer_config_rust(config))
}

fn decode_resharer_config_rust(config: StringView) -> Result<Box<ResharerConfig>, u16> {
  let Ok(config) = Base64::decode_vec(&config.to_string().ok_or(INVALID_ENCODING_ERROR)?) else {
    Err(INVALID_ENCODING_ERROR)?
  };
  let Ok(config) = bincode::deserialize::<ResharerConfig>(&config) else {
    Err(INVALID_ENCODING_ERROR)?
  };

  let Ok(participants_len) = u16::try_from(config.new_participants.len()) else {
    Err(INVALID_PARTICIPANT_ERROR)?
  };
  check_t_n(config.new_threshold, participants_len)?;

  Ok(Box::new(config))
}

#[repr(C)]
pub struct StartResharerRes {
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn start_resharer(
  keys: &ThresholdKeysWrapper,
  config: Box<ResharerConfig>,
) -> CResult<StartResharerRes> {
  todo!()
}

#[repr(C)]
pub struct StartResharedRes {
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn start_reshared(
  multisig_config: Box<MultisigConfig>,
  reshared_config: Box<ResharerConfig>,
  resharer_starts: *const  StringView,
) -> CResult<StartResharedRes> {
  todo!()
}

#[repr(C)]
pub struct CompleteResharerRes {
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn complete_resharer(
  machine: StartResharerRes,
  encryption_keys_of_reshared_to: *const StringView,
) -> CResult<CompleteResharerRes> {
  todo!()
}

#[repr(C)]
pub struct CompleteResharedRes {
  keys: ThresholdKeysWrapper,
}

#[no_mangle]
pub unsafe extern "C" fn complete_reshared(
  machine: StartResharedRes,
  resharer_completes: *const StringView,
) -> CResult<CompleteResharedRes> {
  todo!()
}
