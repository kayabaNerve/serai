use core::{ops::Deref, fmt};
use std::{collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  Ciphersuite,
};
use multiexp::{multiexp_vartime, BatchVerifier};

use crate::{
  Participant, ThresholdParams, ThresholdCore,
  encryption::{EncryptionKeyMessage, EncryptedMessage, Encryption},
  resharing::common::*,
};

// Calculate the exponent for a given participant and apply it to a series of commitments
// Initially used with the actual commitments to verify the secret share, later used with
// stripes to generate the verification shares
fn exponential<C: Ciphersuite>(i: Participant, values: &[C::G]) -> Vec<(C::F, C::G)> {
  let i = C::F::from(u16::from(i).into());
  let mut res = Vec::with_capacity(values.len());
  (0 .. values.len()).fold(C::F::ONE, |exp, l| {
    res.push((exp, values[l]));
    exp * i
  });
  res
}

fn share_verification_statements<C: Ciphersuite>(
  target: Participant,
  commitments: &[C::G],
  mut share: Zeroizing<C::F>,
) -> Vec<(C::F, C::G)> {
  // This can be insecurely linearized from n * t to just n using the below sums for a given
  // stripe. Doing so uses naive addition which is subject to malleability. The only way to
  // ensure that malleability isn't present is to use this n * t algorithm, which runs
  // per sender and not as an aggregate of all senders, which also enables blame
  let mut values = exponential::<C>(target, commitments);

  // Perform the share multiplication outside of the multiexp to minimize stack copying
  // While the multiexp BatchVerifier does zeroize its flattened multiexp, and itself, it still
  // converts whatever we give to an iterator and then builds a Vec internally, welcoming copies
  let neg_share_pub = C::generator() * -*share;
  share.zeroize();
  values.push((C::F::ONE, neg_share_pub));

  values
}

/// A machine used to recieve a reshared key.
#[derive(Zeroize)]
pub struct ResharedMachine<C: Ciphersuite> {
  params: ThresholdParams,
  commitments: Vec<Vec<C::G>>,
  encryption: Encryption<C>,
}

impl<C: Ciphersuite> fmt::Debug for ResharedMachine<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ResharedMachine")
      .field("params", &self.params)
      .field("commitments", &self.commitments)
      .field("encryption", &self.encryption)
      .finish()
  }
}

impl<C: Ciphersuite> ResharedMachine<C> {
  /// Create a new machine to receive a reshared key.
  ///
  /// This machine is not capable of accurately blaming faulty parts. Any blame statements
  /// generated must signify a fault, yet not be trusted to identify the faulty party.
  pub fn new<R: RngCore + CryptoRng>(
    rng: &mut R,
    resharers: u16,
    params: ThresholdParams,
    context: String,
    commitments: Vec<EncryptionKeyMessage<C, Commitments<C>>>,
  ) -> Result<(ResharedMachine<C>, EncryptionKeyMessage<C, ()>), ReshareError> {
    let mut encryption = Encryption::new(context.clone(), params.i, rng);
    let msg = encryption.registration(());

    if usize::from(resharers) != commitments.len() {
      Err(ReshareError::InvalidParticipantQuantity(resharers.into(), commitments.len()))?;
    }

    let mut batch = BatchVerifier::<Participant, C::G>::new(commitments.len());
    let commitments = commitments
      .into_iter()
      .enumerate()
      .map(|(l, msg)| {
        let mut msg = encryption.register(Participant((l + 1).try_into().unwrap()), msg);

        // Step 5: Validate each proof of knowledge
        // This is solely the prep step for the latter batch verification
        msg.sig.batch_verify(
          rng,
          &mut batch,
          Participant(0),
          msg.commitments[0],
          challenge::<C>(&context, msg.sig.R.to_bytes().as_ref(), &msg.cached_msg),
        );

        msg.commitments.drain(..).collect::<Vec<_>>()
      })
      .collect::<Vec<_>>();

    // TODO: Document how this blame will not be valid
    batch.verify_vartime_with_vartime_blame().map_err(ReshareError::InvalidProofOfKnowledge)?;

    Ok((ResharedMachine { params, commitments, encryption }, msg))
  }

  /// Accept private key shares from the resharers.
  ///
  /// The order of the shares must have the same order as the prior specified commitments.
  ///
  /// This will yield a ThresholdCore yet it cannot be trusted until all parties confirm successful
  /// completion of the protocol.
  pub fn accept_shares<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    shares: Vec<EncryptedMessage<C, SecretShare<C::F>>>,
  ) -> Result<ThresholdCore<C>, ReshareError> {
    let ResharedMachine { params, commitments, encryption } = self;
    if commitments.len() != shares.len() {
      Err(ReshareError::InvalidParticipantQuantity(commitments.len(), shares.len()))?;
    }

    let mut secret = Zeroizing::new(C::F::ZERO);
    let mut batch = BatchVerifier::new(shares.len());
    for (l, share_bytes) in shares.into_iter().enumerate() {
      let (mut share_bytes, _) =
        encryption.decrypt(rng, &mut batch, (), Participant(0), share_bytes);
      let share = Zeroizing::new(
        Option::<C::F>::from(C::F::from_repr(share_bytes.0))
          .ok_or(ReshareError::InvalidShare { participant: Participant(0), blame: None })?,
      );
      share_bytes.zeroize();
      *secret += share.deref();

      batch.queue(rng, (), share_verification_statements::<C>(params.i(), &commitments[l], share));
    }
    batch
      .verify_with_vartime_blame()
      .map_err(|_| ReshareError::InvalidShare { participant: Participant(0), blame: None })?;

    // Stripe commitments per t and sum them in advance. Calculating verification shares relies on
    // these sums so preprocessing them is a massive speedup
    // If these weren't just sums, yet the tables used in multiexp, this would be further optimized
    // As of right now, each multiexp will regenerate them
    let mut stripes = Vec::with_capacity(usize::from(params.t()));
    for t in 0 .. usize::from(params.t()) {
      stripes.push(commitments.iter().map(|commitments| commitments[t]).sum());
    }

    // Calculate each user's verification share
    let mut verification_shares = HashMap::new();
    for i in (1 ..= params.n()).map(Participant) {
      verification_shares.insert(
        i,
        if i == params.i() {
          C::generator() * secret.deref()
        } else {
          multiexp_vartime(&exponential::<C>(i, &stripes))
        },
      );
    }

    Ok(ThresholdCore { params, secret_share: secret, group_key: stripes[0], verification_shares })
  }
}
