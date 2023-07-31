/*
use std::collections::HashMap;

use rand_core::{RngCore, CryptoRng};

use ciphersuite::Ciphersuite;

use crate::{
  Participant, ThresholdParams, ThresholdCore,
  frost::{ReshareMachine, SecretShare, KeyMachine},
  encryption::{EncryptionKeyMessage, EncryptedMessage},
  tests::{THRESHOLD, PARTICIPANTS, clone_without},
};

// Needed so rustfmt doesn't fail to format on line length issues
type FrostEncryptedMessage<C> = EncryptedMessage<C, SecretShare<<C as Ciphersuite>::F>>;
type FrostSecretShares<C> = HashMap<Participant, FrostEncryptedMessage<C>>;

const CONTEXT: &str = "DKG Test Key Generation";

// Commit, then return enc key and shares
#[allow(clippy::type_complexity)]
fn commit_enc_keys_and_shares<R: RngCore + CryptoRng, C: Ciphersuite>(
  rng: &mut R,
) -> (
  HashMap<Participant, KeyMachine<C>>,
  HashMap<Participant, C::G>,
  HashMap<Participant, FrostSecretShares<C>>,
) {
  let mut machines = HashMap::new();
  let mut commitments = HashMap::new();
  let mut enc_keys = HashMap::new();
  for i in (1 ..= PARTICIPANTS).map(Participant) {
    let params = ThresholdParams::new(THRESHOLD, PARTICIPANTS, i).unwrap();
    let machine = ReshareMachine::<C>::new(params, CONTEXT.to_string());
    let (machine, these_commitments) = machine.generate_coefficients(rng);
    machines.insert(i, machine);

    commitments.insert(
      i,
      EncryptionKeyMessage::read::<&[u8]>(&mut these_commitments.serialize().as_ref(), params)
        .unwrap(),
    );
    enc_keys.insert(i, commitments[&i].enc_key());
  }

  let mut secret_shares = HashMap::new();
  let machines = machines
    .drain()
    .map(|(l, machine)| {
      let (machine, mut shares) =
        machine.generate_secret_shares(rng, clone_without(&commitments, &l)).unwrap();
      let shares = shares
        .drain()
        .map(|(l, share)| {
          (
            l,
            EncryptedMessage::read::<&[u8]>(
              &mut share.serialize().as_ref(),
              // Only t/n actually matters, so hardcode i to 1 here
              ThresholdParams { t: THRESHOLD, n: PARTICIPANTS, i: Participant(1) },
            )
            .unwrap(),
          )
        })
        .collect::<HashMap<_, _>>();
      secret_shares.insert(l, shares);
      (l, machine)
    })
    .collect::<HashMap<_, _>>();

  (machines, enc_keys, secret_shares)
}

fn generate_secret_shares<C: Ciphersuite>(
  shares: &HashMap<Participant, FrostSecretShares<C>>,
  recipient: Participant,
) -> FrostSecretShares<C> {
  let mut our_secret_shares = HashMap::new();
  for (i, shares) in shares {
    if recipient == *i {
      continue;
    }
    our_secret_shares.insert(*i, shares[&recipient].clone());
  }
  our_secret_shares
}

/// Fully perform the FROST key generation algorithm.
pub fn frost_gen<R: RngCore + CryptoRng, C: Ciphersuite>(
  rng: &mut R,
) -> HashMap<Participant, ThresholdCore<C>> {
  let (mut machines, _, secret_shares) = commit_enc_keys_and_shares::<_, C>(rng);

  let mut verification_shares = None;
  let mut group_key = None;
  machines
    .drain()
    .map(|(i, machine)| {
      let our_secret_shares = generate_secret_shares(&secret_shares, i);
      let these_keys = machine.calculate_share(rng, our_secret_shares).unwrap().complete();

      // Verify the verification_shares are agreed upon
      if verification_shares.is_none() {
        verification_shares = Some(these_keys.verification_shares());
      }
      assert_eq!(verification_shares.as_ref().unwrap(), &these_keys.verification_shares());

      // Verify the group keys are agreed upon
      if group_key.is_none() {
        group_key = Some(these_keys.group_key());
      }
      assert_eq!(group_key.unwrap(), these_keys.group_key());

      (i, these_keys)
    })
    .collect::<HashMap<_, _>>()
}

#[cfg(test)]
mod literal {
  use rand_core::OsRng;

  use ciphersuite::Ristretto;

  use crate::{DkgError, encryption::EncryptionKeyProof, frost::BlameMachine, tests::frost::frost_gen};

  use super::*;

  const ONE: Participant = Participant(1);
  const TWO: Participant = Participant(2);

  #[test]
  fn resharing() {
    let mut keys = frost_gen(&mut OsRng);
  }
}
*/
