use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::{RngCore, SeedableRng, OsRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{Ciphersuite, Secp256k1};
use ::frost::dkg::{*, encryption::*, frost::*};

use base64ct::{Encoding, Base64};
use serde::{Serialize, Deserialize};

use bip39::{Language, Mnemonic};

use crate::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MultisigConfig {
  multisig_name: String,
  threshold: u16,
  participants: Vec<String>,
  // TODO: The wallet MUST check this salt hasn't been prior observed in any prior protocol.
  // It's probably fine in practice since every honest user will use a distinct seed entirely,
  // and malicious parties are already accounted for in the threshold selection.
  // It's still best practice for the wallet to save prior seen salts and check
  salt: [u8; 32],
}

impl MultisigConfig {
  pub fn multisig_name(&self) -> &str {
    &self.multisig_name
  }

  pub fn threshold(&self) -> u16 {
    self.threshold
  }

  pub fn participants(&self) -> &[String] {
    &self.participants
  }

  pub fn salt(&self) -> [u8; 32] {
    self.salt
  }

  fn context(&self) -> String {
    let mut context = RecommendedTranscript::new(b"HRF Multisig Context String");
    context.append_message(b"name", self.multisig_name.as_bytes());
    context.append_message(b"threshold", self.threshold.to_le_bytes());
    for participant in &self.participants {
      context.append_message(b"participant", participant.as_bytes());
    }
    context.append_message(b"salt", self.salt);
    hex::encode(context.challenge(b"challenge"))
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MultisigConfigWithName {
  config: MultisigConfig,
  my_name: String,
}

impl MultisigConfigWithName {
  pub fn config(&self) -> &MultisigConfig {
    &self.config
  }

  pub fn my_name(&self) -> &str {
    &self.my_name
  }

  fn params(&self) -> Result<ThresholdParams, u16> {
    let mut my_index = 0;
    while (my_index < self.config.participants.len()) &&
      (self.config.participants[my_index] != self.my_name)
    {
      my_index += 1;
    }
    if my_index == self.config.participants.len() {
      Err(INVALID_PARTICIPANT_ERROR)?
    }

    let i = Participant::new(u16::try_from(my_index).unwrap() + 1).unwrap();
    Ok(
      ThresholdParams::new(
        self.config.threshold,
        u16::try_from(self.config.participants.len()).unwrap(),
        i,
      )
      .unwrap(),
    )
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

pub fn new_multisig_config(
  multisig_name: &[u8],
  threshold: u16,
  participants: &[&[u8]],
) -> Result<MultisigConfig, u16> {
  let Ok(participants_len) = u16::try_from(participants.len()) else {
    Err(INVALID_PARTICIPANT_ERROR)?
  };

  check_t_n(threshold, participants_len)?;

  let Ok(multisig_name) = String::from_utf8(multisig_name.to_vec()) else {
    Err(INVALID_NAME_ERROR)?
  };
  for participant in participants {
    if participant.is_empty() {
      Err(INVALID_NAME_ERROR)?;
    }
    if String::from_utf8(participant.to_vec()).is_err() {
      Err(INVALID_NAME_ERROR)?;
    }
  }

  // All multisigs should have a unique context string
  // Have the multisig proposer choose a random salt so the only way a conflict will occur is if
  // the proposer is malicious
  // Then, the only way this may be an issue is if a participant doesn't check if they've seen a
  // salt before
  let mut salt = [0; 32];
  OsRng.fill_bytes(&mut salt);

  Ok(MultisigConfig {
    multisig_name,
    threshold,
    participants: participants
      .iter()
      .map(|p| String::from_utf8(p.to_vec()))
      .collect::<Result<_, _>>()
      .unwrap(),
    salt,
  })
}

pub fn serialize_multisig_config(multisig: &MultisigConfig) -> String {
  Base64::encode_string(&bincode::serialize(multisig).unwrap())
}

pub fn deserialize_multisig_config(config: &str) -> Result<MultisigConfig, u16> {
  let Ok(config) = Base64::decode_vec(config) else { Err(INVALID_ENCODING_ERROR)? };
  let Ok(config) = bincode::deserialize::<MultisigConfig>(&config) else {
    Err(INVALID_ENCODING_ERROR)?
  };

  let Ok(participants_len) = u16::try_from(config.participants.len()) else {
    Err(INVALID_PARTICIPANT_ERROR)?
  };
  check_t_n(config.threshold, participants_len)?;

  Ok(config)
}

fn inner_key_gen(
  config: MultisigConfig,
  my_name: &str,
  seed: &[u8; 16],
) -> Result<(MultisigConfigWithName, SecretShareMachine<Secp256k1>, String), u16> {
  let config = MultisigConfigWithName { config, my_name: my_name.to_string() };

  let context = config.config.context();

  let mut coefficients_rng = RecommendedTranscript::new(b"HRF Key Gen Coefficients RNG");
  coefficients_rng.append_message(b"seed", seed);
  coefficients_rng.append_message(b"context", context.as_bytes());
  let mut coefficients_rng = ChaCha20Rng::from_seed(coefficients_rng.rng_seed(b"rng"));

  let (machine, commitments) = KeyGenMachine::<Secp256k1>::new(config.params()?, context)
    .generate_coefficients(&mut coefficients_rng);

  Ok((config, machine, Base64::encode_string(&commitments.serialize())))
}

pub fn start_key_gen(
  config: MultisigConfig,
  my_name: &str,
  language: u16,
) -> Result<(String, MultisigConfigWithName, SecretShareMachine<Secp256k1>, String), u16> {
  // 128-bits of entropy for a 12-word seed
  let mut seed = Zeroizing::new([0; 16]);
  OsRng.fill_bytes(seed.as_mut());

  let (config, machine, commitments) = inner_key_gen(config, my_name, &seed)?;

  // TODO: Screen where the seed is converted to a Bitcoin seed and displayed for backup
  // TODO: Screen where the commitments are displayed for transmision to everyone else

  Ok((
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
    config,
    machine,
    commitments,
  ))
}

pub type RecoverableKeyMachine = (KeyMachine<Secp256k1>, Vec<u8>);

pub fn get_secret_shares(
  config: MultisigConfigWithName,
  language: u16,
  seed: &str,
  machine: SecretShareMachine<Secp256k1>,
  commitments: &[&str],
) -> Result<(RecoverableKeyMachine, String), u16> {
  let mut secret_shares_rng = RecommendedTranscript::new(b"HRF Key Gen Secret Shares RNG");
  let Ok(mnemonic) = Mnemonic::from_phrase(
    seed,
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

  if commitments.len() != config.config.participants.len() {
    Err(INVALID_AMOUNT_OF_COMMITMENTS_ERROR)?;
  }
  let mut commitments_map = HashMap::new();
  for (i, commitments) in commitments.iter().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();
    let Ok(commitments) = Base64::decode_vec(commitments) else { Err(INVALID_ENCODING_ERROR)? };
    let Ok(message) = EncryptionKeyMessage::<Secp256k1, Commitments<Secp256k1>>::read(
      &mut commitments.as_slice(),
      params,
    ) else {
      Err(INVALID_ENCODING_ERROR)?
    };
    commitments_map.insert(i, message);
  }

  let Ok((machine, shares)) =
    machine.generate_secret_shares(&mut secret_shares_rng, commitments_map)
  else {
    Err(INVALID_COMMITMENTS_ERROR)?
  };

  let mut serialized_shares = shares
    .into_iter()
    .map(|(i, shares)| (u16::from(i), shares.serialize()))
    .collect::<HashMap<_, _>>();

  let mut linearized_shares = vec![];
  for i in 1 ..= params.n() {
    linearized_shares.push(serialized_shares.remove(&i).unwrap());
  }

  Ok((
    (machine, bincode::serialize(commitments).unwrap()),
    Base64::encode_string(&bincode::serialize(&linearized_shares).unwrap()),
  ))

  // TODO: Display commitments to be sent to everyone
}

pub fn complete_key_gen(
  config: MultisigConfigWithName,
  machine_and_commitments: RecoverableKeyMachine,
  shares: &[&str],
) -> Result<([u8; 32], ThresholdKeys<Secp256k1>, String), u16> {
  let params = config.params().unwrap();
  let (machine, commitments) = machine_and_commitments;

  if shares.len() != config.config.participants.len() {
    Err(INVALID_AMOUNT_OF_SHARES_ERROR)?;
  }

  let mut shares_map = HashMap::new();
  for (i, shares) in shares.iter().enumerate() {
    let i = Participant::new(u16::try_from(i).unwrap() + 1).unwrap();
    let Ok(linearized_shares) = Base64::decode_vec(shares) else { Err(INVALID_ENCODING_ERROR)? };
    let mut reader_slice = linearized_shares.as_slice();
    let reader = &mut reader_slice;

    let mut shares_from_i = HashMap::new();
    for l in 0 .. config.config.participants.len() {
      let l = Participant::new(u16::try_from(l).unwrap() + 1).unwrap();
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
  }

  let Some(my_shares) = shares_map
    .into_iter()
    .map(|(l, mut shares)| shares.remove(&params.i()).map(|s| (l, s)))
    .collect::<Option<HashMap<_, _>>>()
  else {
    Err(INVALID_SHARE_ERROR)?
  };

  // Doesn't use a seeded RNG since this only uses the RNG for batch verification
  let Ok(machine) = machine.calculate_share(&mut OsRng, my_shares) else {
    Err(INVALID_SHARE_ERROR)?
  };
  let keys = machine.complete();

  let mut recovery = bincode::serialize(&config.config).unwrap();
  recovery.extend(commitments);
  recovery.extend(bincode::serialize(shares).unwrap());

  let mut id = RecommendedTranscript::new(b"HRF Multisig ID");
  id.append_message(b"recovery", &recovery);
  let id = id.challenge(b"id");

  Ok((id.as_slice().try_into().unwrap(), keys.into(), Base64::encode_string(&recovery)))

  // TODO: Have everyone confirm they have the same 32-byte ID
  // TODO: Give everyone the option to save the recovery string
}
