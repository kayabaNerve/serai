use std::collections::{HashSet, HashMap};

use rand_core::{RngCore, OsRng};

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{Ciphersuite, Secp256k1};
use ::frost::dkg::{
  *,
  encryption::*,
  resharing::{*, common::*},
};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use crate::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResharerConfig {
  new_threshold: u16,
  resharers: Vec<u16>,
  new_participants: Vec<String>,
  salt: [u8; 32],
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

  #[no_mangle]
  pub extern "C" fn resharer_salt(&self) -> *const u8 {
    self.salt.as_ptr()
  }

  fn context(&self) -> String {
    let mut context = RecommendedTranscript::new(b"HRF Resharing Context String");
    context.append_message(b"new_threshold", self.new_threshold.to_le_bytes());
    for resharer in &self.resharers {
      context.append_message(b"resharer", resharer.to_le_bytes());
    }
    for new_participant in &self.new_participants {
      context.append_message(b"new_participant", new_participant.as_bytes());
    }
    context.append_message(b"salt", self.salt);
    hex::encode(context.challenge(b"challenge"))
  }
}

fn check_t_n(threshold: u16, participants: u16) -> Result<(), u8> {
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
  config: ResharerConfig,
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
) -> Result<ResharerConfigRes, u8> {
  check_t_n(new_threshold, new_participants_len)?;
  if new_participants_len == u16::MAX {
    Err(INVALID_PARTICIPANTS_AMOUNT_ERROR)?;
  }

  let mut resharers = HashSet::new();
  for resharer in unsafe { std::slice::from_raw_parts(resharers_ptr, resharers_len.into()) } {
    resharers.insert(*resharer);
  }
  if resharers.len() != usize::from(resharers_len) {
    Err(DUPLICATED_PARTICIPANT_ERROR)?;
  }

  let mut resharers = resharers.into_iter().collect::<Vec<_>>();
  resharers.sort();
  if let Some(last) = resharers.last() {
    if *last == u16::MAX {
      Err(INVALID_PARTICIPANT_ERROR)?;
    }
  } else {
    Err(NOT_ENOUGH_RESHARERS_ERROR)?;
  }

  let new_participants =
    unsafe { std::slice::from_raw_parts(new_participants, new_participants_len.into()) };
  let mut new_participants_res = vec![];
  for participant in new_participants {
    if participant.len == 0 {
      Err(INVALID_NAME_ERROR)?;
    }
    let Some(participant) = participant.to_string() else { Err(INVALID_NAME_ERROR)? };
    new_participants_res.push(participant);
  }

  let mut salt = [0; 32];
  OsRng.fill_bytes(&mut salt);

  let config =
    ResharerConfig { new_threshold, resharers, new_participants: new_participants_res, salt };
  let encoded = OwnedString::new(Base64::encode_string(&bincode::serialize(&config).unwrap()));
  Ok(ResharerConfigRes { config, encoded })
}

#[no_mangle]
pub extern "C" fn decode_resharer_config(config: StringView) -> CResult<ResharerConfig> {
  CResult::new(decode_resharer_config_rust(config))
}

fn decode_resharer_config_rust(config: StringView) -> Result<ResharerConfig, u8> {
  let Ok(config) = Base64::decode_vec(&config.to_string().ok_or(INVALID_ENCODING_ERROR)?) else {
    Err(INVALID_ENCODING_ERROR)?
  };
  let Ok(mut config) = bincode::deserialize::<ResharerConfig>(&config) else {
    Err(INVALID_ENCODING_ERROR)?
  };

  let Ok(participants_len) = u16::try_from(config.new_participants.len()) else {
    Err(INVALID_PARTICIPANT_ERROR)?
  };
  check_t_n(config.new_threshold, participants_len)?;

  config.resharers =
    config.resharers.into_iter().collect::<HashSet<_>>().into_iter().collect::<Vec<_>>();
  config.resharers.sort();
  if let Some(last) = config.resharers.last() {
    if *last == u16::MAX {
      Err(INVALID_PARTICIPANT_ERROR)?;
    }
  } else {
    Err(NOT_ENOUGH_RESHARERS_ERROR)?;
  }

  Ok(config)
}

struct OpaqueResharingMachine(ResharingSecretMachine<Secp256k1>);

#[repr(C)]
pub struct StartResharerRes {
  new_participants_len: usize,
  machine: Box<OpaqueResharingMachine>,
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn start_resharer(
  keys: &ThresholdKeysWrapper,
  config: Box<ResharerConfig>,
) -> CResult<StartResharerRes> {
  CResult::new(start_resharer_rust(keys, config))
}

fn start_resharer_rust(
  keys: &ThresholdKeysWrapper,
  config: Box<ResharerConfig>,
) -> Result<StartResharerRes, u8> {
  if config.resharers.len() < keys.0.params().t().into() {
    Err(NOT_ENOUGH_RESHARERS_ERROR)?;
  }
  let (machine, message) = ResharingMachine::new(
    keys.0.clone(),
    config.resharers.iter().map(|i| Participant::new(*i + 1).unwrap()).collect(),
    ThresholdParams::new(
      config.new_threshold,
      u16::try_from(config.new_participants.len()).unwrap(),
      Participant::new(1).unwrap(),
    )
    .map_err(|_| UNKNOWN_ERROR)?,
    config.context(),
  )
  .ok_or(UNKNOWN_ERROR)?
  .generate_coefficients(&mut OsRng);
  Ok(StartResharerRes {
    new_participants_len: config.new_participants.len(),
    machine: Box::new(OpaqueResharingMachine(machine)),
    encoded: OwnedString::new(Base64::encode_string(&message.serialize())),
  })
}

struct OpaqueResharedMachine(ResharedMachine<Secp256k1>);

#[repr(C)]
pub struct StartResharedRes {
  resharers_len: usize,
  machine: Box<OpaqueResharedMachine>,
  encoded: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn start_reshared(
  resharer_config: Box<ResharerConfig>,
  my_name: StringView,
  resharer_starts: *const StringView,
) -> CResult<StartResharedRes> {
  CResult::new(start_reshared_rust(resharer_config, my_name, resharer_starts))
}

fn start_reshared_rust(
  resharer_config: Box<ResharerConfig>,
  my_name: StringView,
  resharer_starts: *const StringView,
) -> Result<StartResharedRes, u8> {
  let mut msgs = vec![];
  for view in
    (unsafe { std::slice::from_raw_parts(resharer_starts, resharer_config.resharers.len()) }).iter()
  {
    let bytes = Base64::decode_vec(&view.to_string().ok_or(INVALID_ENCODING_ERROR)?)
      .map_err(|_| INVALID_ENCODING_ERROR)?;
    let msg = EncryptionKeyMessage::<Secp256k1, Commitments<Secp256k1>>::read(
      &mut bytes.as_slice(),
      ThresholdParams::new(
        resharer_config.new_threshold,
        resharer_config.new_participants.len().try_into().unwrap(),
        Participant::new(1).unwrap(),
      )
      .unwrap(),
    )
    .map_err(|_| INVALID_RESHARER_MSG_ERROR)?;
    msgs.push(msg);
  }

  let my_name = my_name.to_string().ok_or(INVALID_NAME_ERROR)?;
  let Ok((machine, msg)) = ResharedMachine::new(
    &mut OsRng,
    u16::try_from(resharer_config.resharers.len()).unwrap(),
    ThresholdParams::new(
      resharer_config.new_threshold,
      u16::try_from(resharer_config.new_participants.len()).unwrap(),
      Participant::new(
        u16::try_from(
          resharer_config
            .new_participants
            .iter()
            .position(|name| name == &my_name)
            .ok_or(INVALID_PARTICIPANT_ERROR)?,
        )
        .unwrap() +
          1,
      )
      .unwrap(),
    )
    .unwrap(),
    resharer_config.context(),
    msgs,
  ) else {
    Err(INVALID_RESHARER_MSG_ERROR)?
  };

  Ok(StartResharedRes {
    resharers_len: resharer_config.resharers.len(),
    machine: Box::new(OpaqueResharedMachine(machine)),
    encoded: OwnedString::new(Base64::encode_string(&msg.serialize())),
  })
}

#[no_mangle]
pub unsafe extern "C" fn complete_resharer(
  machine: StartResharerRes,
  encryption_keys_of_reshared_to: *const StringView,
) -> CResult<OwnedString> {
  CResult::new(complete_resharer_rust(machine, encryption_keys_of_reshared_to))
}

fn complete_resharer_rust(
  prior: StartResharerRes,
  encryption_keys_of_reshared_to: *const StringView,
) -> Result<OwnedString, u8> {
  let mut msgs = HashMap::new();
  for (i, view) in (unsafe {
    std::slice::from_raw_parts(encryption_keys_of_reshared_to, prior.new_participants_len)
  })
  .iter()
  .enumerate()
  {
    let bytes = Base64::decode_vec(&view.to_string().ok_or(INVALID_ENCODING_ERROR)?)
      .map_err(|_| INVALID_ENCODING_ERROR)?;
    let msg = EncryptionKeyMessage::<Secp256k1, ()>::read(
      &mut bytes.as_slice(),
      ThresholdParams::new(1, 1, Participant::new(1).unwrap()).unwrap(),
    )
    .map_err(|_| INVALID_RESHARED_MSG_ERROR)?;
    msgs.insert(Participant::new((i + 1).try_into().unwrap()).unwrap(), msg);
  }
  Ok(OwnedString::new(Base64::encode_string(
    &bincode::serialize(
      &prior
        .machine
        .0
        .generate_secret_shares(&mut OsRng, msgs)
        .map_err(|_| INVALID_RESHARED_MSG_ERROR)?
        .into_iter()
        .map(|(key, value)| (u16::from(key), value.serialize()))
        .collect::<HashMap<_, _>>(),
    )
    .unwrap(),
  )))
}

#[no_mangle]
pub unsafe extern "C" fn complete_reshared(
  prior: StartResharedRes,
  resharer_completes: *const StringView,
) -> CResult<ThresholdKeysWrapper> {
  CResult::new(complete_reshared_rust(prior, resharer_completes))
}

fn complete_reshared_rust(
  prior: StartResharedRes,
  resharer_completes: *const StringView,
) -> Result<ThresholdKeysWrapper, u8> {
  let mut msgs = vec![];
  for view in
    (unsafe { std::slice::from_raw_parts(resharer_completes, prior.resharers_len) }).iter()
  {
    let bytes = Base64::decode_vec(&view.to_string().ok_or(INVALID_ENCODING_ERROR)?)
      .map_err(|_| INVALID_ENCODING_ERROR)?;
    let msg = EncryptedMessage::<Secp256k1, SecretShare<<Secp256k1 as Ciphersuite>::F>>::read(
      &mut bytes.as_slice(),
      ThresholdParams::new(1, 1, Participant::new(1).unwrap()).unwrap(),
    )
    .map_err(|_| INVALID_RESHARER_MSG_ERROR)?;
    msgs.push(msg);
  }

  Ok(ThresholdKeysWrapper(ThresholdKeys::new(
    prior.machine.0.accept_shares(&mut OsRng, msgs).map_err(|_| INVALID_RESHARER_MSG_ERROR)?,
  )))
}
