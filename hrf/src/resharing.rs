use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{Ciphersuite, Secp256k1};
use ::frost::dkg::{*, encryption::*, resharing::*};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use crate::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResharerConfig {
  new_threshold: u16,
  resharers: Vec<Participant>,
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
  pub extern "C" fn resharer_resharer(&self, i: usize) -> usize {
    usize::from(u16::from(self.resharers[i])) + 1
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
    keys,
    new_threshold,
    resharers,
    new_participants,
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
  if new_participants_len == u16::MAX { Err()?; }

  if resharers_len < keys.params().t() { Err()?; }
  let mut resharers = HashSet::new();
  for resharer in unsafe { std::slice::from_raw_parts(resharers_ptr, resharers_len) } {
    if resharer == 0 { Err()?; }
    resharers.insert(*resharer);
  }
  if resharers.len() != usize::from(resharers_len) { Err()?; }

  let resharers = resharers.into_iter().map(|i| Participant::new(i).unwrap()).collect::<Vec<_>>();

  let participants = unsafe { std::slice::from_raw_parts(participants, participants_len.into()) };
  let mut participants_res = vec![];
  for participant in participants {
    if participant.len == 0 {
      Err(INVALID_NAME_ERROR)?;
    }
    let Some(participant) = participant.to_string() else { Err(INVALID_NAME_ERROR)? };
    participants_res.push(participant);
  }

  let mut config = ResharerConfig { new_threshold, resharers, new_participants: participants_res };
  let encoded = OwnedString::new(Base64::encode_string(&bincode::serialize(&config).unwrap()));
  Ok(ResharerConfigRes { config: config.into(), encoded })
}

#[no_mangle]
pub extern "C" fn decode_resharer_config(config: StringView) -> CResult<ResharerConfig> {
  CResult::new(decode_resharer_config_rust(config))
}

fn decode_resharer_config_rust(config: StringView) -> Result<ResharerConfig, u16> {
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

  Ok(config)
}
/*
/*
fn inner_key_gen(
  config: Box<ResharerConfig>,
  my_name: StringView,
  seed: &[u8; 16],
) -> Result<(ResharerConfigWithName, SecretShareMachine<Secp256k1>, OwnedString), u16> {
  let config = ResharerConfigWithName {
    config,
    my_name: my_name.to_string().ok_or(INVALID_NAME_ERROR)?.into(),
  };

  let context = config.config.context();

  let mut coefficients_rng = RecommendedTranscript::new(b"HRF Key Gen Coefficients RNG");
  coefficients_rng.append_message(b"seed", seed);
  coefficients_rng.append_message(b"context", context.as_bytes());
  let mut coefficients_rng = ChaCha20Rng::from_seed(coefficients_rng.rng_seed(b"rng"));

  let (machine, commitments) = KeyGenMachine::<Secp256k1>::new(config.params()?, context)
    .generate_coefficients(&mut coefficients_rng);

  Ok((config, machine, OwnedString::new(Base64::encode_string(&commitments.serialize()))))
}

pub struct SecretShareMachineWrapper(SecretShareMachine<Secp256k1>);
*/

#[repr(C)]
pub struct StartReshareRes {
  seed: OwnedString,
  config: Box<ResharerConfigWithName>,
  machine: Box<SecretShareMachineWrapper>,
  commitments: OwnedString,
}

#[no_mangle]
pub extern "C" fn start_key_gen(
  config: Box<ResharerConfig>,
  my_name: StringView,
  language: u16,
) -> CResult<StartKeyGenRes> {
  CResult::new(start_key_gen_rust(config, my_name, language))
}

fn start_key_gen_rust(
  config: Box<ResharerConfig>,
  my_name: StringView,
  language: u16,
) -> Result<StartKeyGenRes, u16> {
  // 128-bits of entropy for a 12-word seed
  let mut seed = Zeroizing::new([0; 16]);
  OsRng.fill_bytes(seed.as_mut());

  let (config, machine, commitments) = inner_key_gen(config, my_name, &seed)?;

  // TODO: Screen where the seed is converted to a Bitcoin seed and displayed for backup
  // TODO: Screen where the commitments are displayed for transmision to everyone else

  Ok(StartKeyGenRes {
    seed: OwnedString::new(
      Mnemonic::from_entropy(
        seed.as_ref(),
        match language {
          LANGUAGE_ENGLISH => Language::English,
          LANGUAGE_CHINESE_SIMPLIFIED => Language::ChineseSimplified,
          LANGUAGE_CHINESE_TRADITIONAL => Language::ChineseTraditional,
          LANGUAGE_FRENCH => Language::French,
          LANGUAGE_ITALIAN => Language::Italian,
          LANGUAGE_JAPANESE => Language::Japanese,
          LANGUAGE_KOREAN => Language::Korean,
          LANGUAGE_SPANISH => Language::Spanish,
          _ => Err(UNKNOWN_LANGUAGE_ERROR)?,
        },
      )
      .unwrap()
      .to_string(),
    ),
    config: config.into(),
    machine: SecretShareMachineWrapper(machine).into(),
    commitments,
  })
}

struct KeyMachineWrapper(KeyMachine<Secp256k1>);

#[repr(C)]
pub struct SecretSharesRes {
  machine: Box<KeyMachineWrapper>,
  internal_commitments: Box<Vec<u8>>,
  shares: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn get_secret_shares(
  config: &ResharerConfigWithName,
  language: u16,
  seed: StringView,
  machine: Box<SecretShareMachineWrapper>,
  commitments: *const StringView,
  commitments_len: usize,
) -> CResult<SecretSharesRes> {
  CResult::new(get_secret_shares_rust(
    config,
    language,
    seed,
    machine,
    commitments,
    commitments_len,
  ))
}

fn get_secret_shares_rust(
  config: &ResharerConfigWithName,
  language: u16,
  seed: StringView,
  machine: Box<SecretShareMachineWrapper>,
  commitments: *const StringView,
  commitments_len: usize,
) -> Result<SecretSharesRes, u16> {
  let mut secret_shares_rng = RecommendedTranscript::new(b"HRF Key Gen Secret Shares RNG");
  let Ok(mnemonic) = Mnemonic::from_phrase(
    &seed.to_string().ok_or(INVALID_SEED_ERROR)?,
    match language {
      LANGUAGE_ENGLISH => Language::English,
      LANGUAGE_CHINESE_SIMPLIFIED => Language::ChineseSimplified,
      LANGUAGE_CHINESE_TRADITIONAL => Language::ChineseTraditional,
      LANGUAGE_FRENCH => Language::French,
      LANGUAGE_ITALIAN => Language::Italian,
      LANGUAGE_JAPANESE => Language::Japanese,
      LANGUAGE_KOREAN => Language::Korean,
      LANGUAGE_SPANISH => Language::Spanish,
      _ => Err(UNKNOWN_LANGUAGE_ERROR)?,
    },
  ) else {
    Err(INVALID_SEED_ERROR)?
  };
  secret_shares_rng.append_message(b"seed", mnemonic.entropy());
  secret_shares_rng.append_message(b"context", config.config.context().as_bytes());
  let mut secret_shares_rng = ChaCha20Rng::from_seed(secret_shares_rng.rng_seed(b"rng"));

  let params = config.params().unwrap();

  let commitments = unsafe { std::slice::from_raw_parts(commitments, commitments_len) };
  if commitments.len() != config.config.participants.len() {
    Err(INVALID_AMOUNT_OF_COMMITMENTS_ERROR)?;
  }
  let mut new_commitments = vec![];
  let mut commitments_map = HashMap::new();
  for (i, commitments) in commitments.iter().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();
    let Ok(commitments) =
      Base64::decode_vec(&commitments.to_string().ok_or(INVALID_ENCODING_ERROR)?)
    else {
      Err(INVALID_ENCODING_ERROR)?
    };
    let Ok(message) = EncryptionKeyMessage::<Secp256k1, Commitments<Secp256k1>>::read(
      &mut commitments.as_slice(),
      params,
    ) else {
      Err(INVALID_ENCODING_ERROR)?
    };
    commitments_map.insert(i, message);

    new_commitments.push(commitments);
  }
  let commitments = new_commitments;

  commitments_map.remove(&params.i());
  let Ok((machine, mut shares)) =
    machine.0.generate_secret_shares(&mut secret_shares_rng, commitments_map)
  else {
    Err(INVALID_COMMITMENTS_ERROR)?
  };

  let mut linearized_shares = vec![];
  for l in 1 ..= params.n() {
    let l = Participant::new(l).unwrap();
    if l != params.i() {
      shares.remove(&l).unwrap().write(&mut linearized_shares).unwrap();
    }
  }

  Ok(SecretSharesRes {
    machine: Box::new(KeyMachineWrapper(machine)),
    internal_commitments: Box::new(bincode::serialize(&commitments).unwrap()),
    shares: OwnedString::new(Base64::encode_string(&linearized_shares)),
  })

  // TODO: Display commitments to be sent to everyone
}

#[repr(C)]
pub struct KeyGenRes {
  multisig_id: [u8; 32],
  keys: Box<ThresholdKeysWrapper>,
  recovery: OwnedString,
}

#[no_mangle]
pub unsafe extern "C" fn complete_key_gen(
  config: &ResharerConfigWithName,
  machine_and_commitments: SecretSharesRes,
  shares: *const StringView,
  shares_len: usize,
) -> CResult<KeyGenRes> {
  CResult::new(complete_key_gen_rust(config, machine_and_commitments, shares, shares_len))
}

unsafe fn complete_key_gen_rust(
  config: &ResharerConfigWithName,
  machine_and_commitments: SecretSharesRes,
  shares: *const StringView,
  shares_len: usize,
) -> Result<KeyGenRes, u16> {
  let params = config.params().unwrap();
  let SecretSharesRes { machine, internal_commitments: commitments, .. } = machine_and_commitments;

  if shares_len != config.config.participants.len() {
    Err(INVALID_AMOUNT_OF_SHARES_ERROR)?;
  }
  let shares = unsafe { std::slice::from_raw_parts(shares, shares_len) };

  let mut new_shares = vec![];
  let mut shares_map = HashMap::new();
  for (i, shares) in shares.iter().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();
    let Ok(linearized_shares) =
      Base64::decode_vec(&shares.to_string().ok_or(INVALID_ENCODING_ERROR)?)
    else {
      Err(INVALID_ENCODING_ERROR)?
    };
    let mut reader_slice = linearized_shares.as_slice();
    let reader = &mut reader_slice;

    let mut shares_from_i = HashMap::new();
    for l in 0 .. config.config.participants.len() {
      let l = Participant::new(u16::try_from(l).unwrap() + 1).unwrap();
      if l == i {
        continue;
      }
      let Ok(message) =
        EncryptedMessage::<Secp256k1, SecretShare<<Secp256k1 as Ciphersuite>::F>>::read(
          reader, params,
        )
      else {
        Err(INVALID_ENCODING_ERROR)?
      };
      shares_from_i.insert(l, message);
    }
    shares_map.insert(i, shares_from_i);

    new_shares.push(linearized_shares);
  }
  let shares = new_shares;
  shares_map.remove(&params.i());

  let Some(my_shares) = shares_map
    .into_iter()
    .map(|(l, mut shares)| shares.remove(&params.i()).map(|s| (l, s)))
    .collect::<Option<HashMap<_, _>>>()
  else {
    Err(INVALID_SHARE_ERROR)?
  };

  // Doesn't use a seeded RNG since this only uses the RNG for batch verification
  let Ok(machine) = machine.0.calculate_share(&mut OsRng, my_shares) else {
    Err(INVALID_SHARE_ERROR)?
  };
  let keys = machine.complete();

  let mut recovery = bincode::serialize(&config.config).unwrap();
  recovery.extend(*commitments);
  recovery.extend(bincode::serialize(&shares).unwrap());

  let mut id = RecommendedTranscript::new(b"HRF Multisig ID");
  id.append_message(b"recovery", &recovery);
  let id = id.challenge(b"id");

  Ok(KeyGenRes {
    multisig_id: id.as_slice()[.. 32].try_into().unwrap(),
    keys: Box::new(ThresholdKeysWrapper(keys.into())),
    recovery: OwnedString::new(Base64::encode_string(&recovery)),
  })

  // TODO: Have everyone confirm they have the same 32-byte ID
  // TODO: Give everyone the option to save the recovery string
}

#[no_mangle]
pub unsafe extern "C" fn serialize_keys(keys: &ThresholdKeysWrapper) -> OwnedString {
  OwnedString::new(hex::encode(&keys.0.serialize()))
}

#[no_mangle]
pub unsafe extern "C" fn deserialize_keys(keys: StringView) -> CResult<ThresholdKeysWrapper> {
  let Some(string) = keys.to_string() else { return CResult::new(Err(INVALID_ENCODING_ERROR)) };
  let Ok(bytes) = hex::decode(string) else { return CResult::new(Err(INVALID_ENCODING_ERROR)) };
  let Ok(keys) = ThresholdCore::<Secp256k1>::read(&mut bytes.as_slice()) else {
    return CResult::new(Err(UNKNOWN_ERROR));
  };
  CResult::new(Ok(ThresholdKeysWrapper(keys.into())))
}
*/
