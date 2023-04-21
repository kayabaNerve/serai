use std::{
  io::{self, Read},
  sync::{Arc, RwLock},
  collections::HashMap,
};

use zeroize::Zeroizing;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use group::ff::Field;
use curve25519_dalek::{traits::Identity, scalar::Scalar, edwards::EdwardsPoint};
use dalek_ff_group as dfg;

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys,
  sign::{
    Writable, Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine,
    SignatureMachine, AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};

use crate::{
  random_scalar,
  ringct::{
    clsag::{ClsagInput, ClsagDetails, ClsagAddendum, ClsagMultisig, add_key_image_share},
    RctPrunable,
  },
  transaction::{Input, Transaction},
  wallet::{
    TransactionError, InternalPayment, SignableTransaction, Decoys, key_image_sort, uniqueness,
  },
};

/// FROST signing machine to produce a signed transaction.
pub struct TransactionMachine {
  signable: SignableTransaction,

  i: Participant,
  transcript: RecommendedTranscript,

  decoys: Vec<Decoys>,

  // Hashed key and scalar offset
  key_images: Vec<(EdwardsPoint, Scalar)>,
  inputs: Vec<Arc<RwLock<Option<ClsagDetails>>>>,
  clsags: Vec<AlgorithmMachine<Ed25519, ClsagMultisig>>,
}

pub struct TransactionSignMachine {
  signable: SignableTransaction,

  i: Participant,
  transcript: RecommendedTranscript,

  decoys: Vec<Decoys>,

  key_images: Vec<(EdwardsPoint, Scalar)>,
  inputs: Vec<Arc<RwLock<Option<ClsagDetails>>>>,
  clsags: Vec<AlgorithmSignMachine<Ed25519, ClsagMultisig>>,

  our_preprocess: Vec<Preprocess<Ed25519, ClsagAddendum>>,
}

pub struct TransactionSignatureMachine {
  tx: Transaction,
  clsags: Vec<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = Vec<Preprocess<Ed25519, ClsagAddendum>>;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (TransactionSignMachine, Self::Preprocess) {
    // Iterate over each CLSAG calling preprocess
    let mut preprocesses = Vec::with_capacity(self.clsags.len());
    let clsags = self
      .clsags
      .drain(..)
      .map(|clsag| {
        let (clsag, preprocess) = clsag.preprocess(rng);
        preprocesses.push(preprocess);
        clsag
      })
      .collect();
    let our_preprocess = preprocesses.clone();

    // We could add further entropy here, and previous versions of this library did so
    // As of right now, the multisig's key, the inputs being spent, and the FROST data itself
    // will be used for RNG seeds. In order to recreate these RNG seeds, breaking privacy,
    // counterparties must have knowledge of the multisig, either the view key or access to the
    // coordination layer, and then access to the actual FROST signing process
    // If the commitments are sent in plain text, then entropy here also would be, making it not
    // increase privacy. If they're not sent in plain text, or are otherwise inaccessible, they
    // already offer sufficient entropy. That's why further entropy is not included

    (
      TransactionSignMachine {
        signable: self.signable,

        i: self.i,
        transcript: self.transcript,

        decoys: self.decoys,

        key_images: self.key_images,
        inputs: self.inputs,
        clsags,

        our_preprocess,
      },
      preprocesses,
    )
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Ed25519>;
  type Preprocess = Vec<Preprocess<Ed25519, ClsagAddendum>>;
  type SignatureShare = Vec<SignatureShare<Ed25519>>;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(_: (), _: ThresholdKeys<Ed25519>, _: CachedPreprocess) -> Result<Self, FrostError> {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.clsags.iter().map(|clsag| clsag.read_preprocess(reader)).collect()
  }

  fn sign(
    mut self,
    mut commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      panic!("message was passed to the TransactionMachine when it generates its own");
    }

    // Find out who's included
    // This may not be a valid set of signers yet the algorithm machine will error if it's not
    commitments.remove(&self.i); // Remove, if it was included for some reason
    let mut included = commitments.keys().cloned().collect::<Vec<_>>();
    included.push(self.i);
    included.sort_unstable();

    // Convert the unified commitments to a Vec of the individual commitments
    let mut images = vec![EdwardsPoint::identity(); self.clsags.len()];
    let mut commitments = (0 .. self.clsags.len())
      .map(|c| {
        included
          .iter()
          .map(|l| {
            // Add all commitments to the transcript for their entropy
            // While each CLSAG will do this as they need to for security, they have their own
            // transcripts cloned from this TX's initial premise's transcript. For our TX
            // transcript to have the CLSAG data for entropy, it'll have to be added ourselves here
            self.transcript.append_message(b"participant", (*l).to_bytes());

            let preprocess = if *l == self.i {
              self.our_preprocess[c].clone()
            } else {
              commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?[c].clone()
            };

            {
              let mut buf = vec![];
              preprocess.write(&mut buf).unwrap();
              self.transcript.append_message(b"preprocess", buf);
            }

            // While here, calculate the key image
            // Clsag will parse/calculate/validate this as needed, yet doing so here as well
            // provides the easiest API overall, as this is where the TX is (which needs the key
            // images in its message), along with where the outputs are determined (where our
            // outputs may need these in order to guarantee uniqueness)
            add_key_image_share(
              &mut images[c],
              self.key_images[c].0,
              self.key_images[c].1,
              &included,
              *l,
              preprocess.addendum.key_image.0,
            );

            Ok((*l, preprocess))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    // Remove our preprocess which shouldn't be here. It was just the easiest way to implement the
    // above
    for map in commitments.iter_mut() {
      map.remove(&self.i);
    }

    // Create the actual transaction
    let (mut tx, output_masks) = {
      let mut sorted_images = images.clone();
      sorted_images.sort_by(key_image_sort);

      self.signable.prepare_transaction(
        // Technically, r_seed is used for the transaction keys if it's provided
        &mut ChaCha20Rng::from_seed(self.transcript.rng_seed(b"transaction_keys_bulletproofs")),
        uniqueness(
          &sorted_images
            .iter()
            .map(|image| Input::ToKey { amount: 0, key_offsets: vec![], key_image: *image })
            .collect::<Vec<_>>(),
        ),
      )
    };

    // Sort the inputs, as expected
    let mut sorted = Vec::with_capacity(self.clsags.len());
    while !self.clsags.is_empty() {
      sorted.push((
        images.swap_remove(0),
        self.signable.inputs.swap_remove(0),
        self.decoys.swap_remove(0),
        self.inputs.swap_remove(0),
        self.clsags.swap_remove(0),
        commitments.swap_remove(0),
      ));
    }
    sorted.sort_by(|x, y| key_image_sort(&x.0, &y.0));

    let mut rng = ChaCha20Rng::from_seed(self.transcript.rng_seed(b"pseudo_out_masks"));
    let mut sum_pseudo_outs = Scalar::zero();
    while !sorted.is_empty() {
      let value = sorted.remove(0);

      let mut mask = random_scalar(&mut rng);
      if sorted.is_empty() {
        mask = output_masks - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }

      tx.prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: value.2.offsets.clone(),
        key_image: value.0,
      });

      *value.3.write().unwrap() = Some(ClsagDetails::new(
        ClsagInput::new(value.1.commitment().clone(), value.2).map_err(|_| {
          panic!("Signing an input which isn't present in the ring we created for it")
        })?,
        mask,
      ));

      self.clsags.push(value.4);
      commitments.push(value.5);
    }

    let msg = tx.signature_hash();

    // Iterate over each CLSAG calling sign
    let mut shares = Vec::with_capacity(self.clsags.len());
    let clsags = self
      .clsags
      .drain(..)
      .map(|clsag| {
        let (clsag, share) = clsag.sign(commitments.remove(0), &msg)?;
        shares.push(share);
        Ok(clsag)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx, clsags }, shares))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Ed25519>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.clsags.iter().map(|clsag| clsag.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    let mut tx = self.tx;
    match tx.rct_signatures.prunable {
      RctPrunable::Null => panic!("Signing for RctPrunable::Null"),
      RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. } => {
        for (c, clsag) in self.clsags.drain(..).enumerate() {
          let (clsag, pseudo_out) = clsag.complete(
            shares.iter().map(|(l, shares)| (*l, shares[c].clone())).collect::<HashMap<_, _>>(),
          )?;
          clsags.push(clsag);
          pseudo_outs.push(pseudo_out);
        }
      }
    }
    Ok(tx)
  }
}
