use core::{marker::PhantomData, ops::Deref, fmt};
use std::collections::{HashSet, HashMap};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite,
};

use schnorr::SchnorrSignature;

use crate::{
  Participant, ThresholdParams, ThresholdKeys, validate_map, lagrange,
  encryption::{EncryptionKeyMessage, EncryptedMessage, Encryption},
  resharing::common::*,
};

/// State machine to begin the resharing protocol.
#[derive(Debug, Zeroize)]
pub struct ResharingMachine<C: Ciphersuite> {
  share: Zeroizing<C::F>,
  params: ThresholdParams,
  context: String,
  _curve: PhantomData<C>,
}

impl<C: Ciphersuite> ResharingMachine<C> {
  /// Create a new machine to reshare a key.
  ///
  /// Returns None if the keys have an offset or if the specified resharers are invalid.
  ///
  /// The context string should be unique among multisigs.
  // TODO: Return an eerror
  pub fn new(
    existing_keys: ThresholdKeys<C>,
    mut resharers: Vec<Participant>,
    params: ThresholdParams,
    context: String,
  ) -> Option<ResharingMachine<C>> {
    if existing_keys.current_offset().is_some() {
      return None;
    }

    if resharers.len() < existing_keys.params().t.into() {
      return None;
    }

    resharers.sort_unstable();
    // TODO: Use a sort, check equality test rather than a HashSet
    if resharers.iter().cloned().collect::<HashSet<_>>().len() != resharers.len() {
      return None;
    }

    for participant in &resharers {
      if u16::from(*participant) > existing_keys.params().n {
        return None;
      }
    }

    let share = Zeroizing::new(
      lagrange::<C::F>(existing_keys.params().i, &resharers) * existing_keys.secret_share().deref(),
    );
    Some(ResharingMachine { share, params, context, _curve: PhantomData })
  }

  /// Returns a commitments message to be sent to all parties over an authenticated channel. If any
  /// party submits multiple sets of commitments, they MUST be treated as malicious.
  pub fn generate_coefficients<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (ResharingSecretMachine<C>, EncryptionKeyMessage<C, Commitments<C>>) {
    let t = usize::from(self.params.t);
    let mut coefficients = Vec::with_capacity(t);
    let mut commitments = Vec::with_capacity(t);
    let mut cached_msg = vec![];

    coefficients.push(self.share);
    commitments.push(C::generator() * coefficients[0].deref());
    cached_msg.extend(commitments[0].to_bytes().as_ref());
    for i in 1 .. t {
      // Step 1: Generate t random values to form a polynomial with
      coefficients.push(Zeroizing::new(C::random_nonzero_F(&mut *rng)));
      // Step 3: Generate public commitments
      commitments.push(C::generator() * coefficients[i].deref());
      cached_msg.extend(commitments[i].to_bytes().as_ref());
    }

    // Step 2: Provide a proof of knowledge
    let r = Zeroizing::new(C::random_nonzero_F(rng));
    let nonce = C::generator() * r.deref();
    let sig = SchnorrSignature::<C>::sign(
      &coefficients[0],
      // This could be deterministic as the PoK is a singleton never opened up to cooperative
      // discussion
      // There's no reason to spend the time and effort to make this deterministic besides a
      // general obsession with canonicity and determinism though
      r,
      challenge::<C>(&self.context, nonce.to_bytes().as_ref(), &cached_msg),
    );

    // Additionally create an encryption mechanism to protect the secret shares
    // Use 0 for our participant ID since we don't necessarily have a participant ID in the new
    // multisig
    // Reduces the integrity of the proofs of possession used by encryption, yet shouldn't
    // invalidate them
    // It doesn't matter either way since resharing doesn't expose a blame API
    let encryption = Encryption::new(self.context.clone(), Participant(0), rng);

    // Step 4: Broadcast
    let msg =
      encryption.registration(Commitments { commitments: commitments.clone(), cached_msg, sig });
    (
      ResharingSecretMachine {
        params: self.params,
        context: self.context,
        coefficients,
        encryption,
      },
      msg,
    )
  }
}

#[derive(Zeroize)]
pub struct ResharingSecretMachine<C: Ciphersuite> {
  params: ThresholdParams,
  context: String,
  coefficients: Vec<Zeroizing<C::F>>,
  encryption: Encryption<C>,
}

impl<C: Ciphersuite> fmt::Debug for ResharingSecretMachine<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ResharingSecretMachine")
      .field("params", &self.params)
      .field("context", &self.context)
      .field("encryption", &self.encryption)
      .finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> ResharingSecretMachine<C> {
  /// Generate the secret shares for this resharing.
  ///
  /// Takes in everyone the reshare's targets' encryption keys. Returns a HashMap of encrypted
  /// secret shares to be sent over authenticated channels to their relevant counterparties.
  ///
  /// If any participant sends multiple secret shares to another participant, they are faulty.
  #[allow(clippy::type_complexity)]
  pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    mut encryption_keys: HashMap<Participant, EncryptionKeyMessage<C, ()>>,
  ) -> Result<HashMap<Participant, EncryptedMessage<C, SecretShare<C::F>>>, ReshareError> {
    validate_map(
      &encryption_keys,
      &(1 ..= self.params.n).map(Participant).collect::<Vec<_>>(),
      None,
    )?;

    // Step 1: Generate secret shares for all other parties
    let mut res = HashMap::new();
    for l in (1 ..= self.params.n()).map(Participant) {
      // Safe unwrap due to validate_map
      self.encryption.register(l, encryption_keys.remove(&l).unwrap());

      let mut share = polynomial(&self.coefficients, l);
      let share_bytes = Zeroizing::new(SecretShare::<C::F>(share.to_repr()));
      share.zeroize();
      res.insert(l, self.encryption.encrypt(rng, l, share_bytes));
    }
    self.coefficients.zeroize();
    self.encryption.zeroize();
    Ok(res)
  }
}
