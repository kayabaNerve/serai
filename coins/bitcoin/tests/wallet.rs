use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use transcript::{Transcript, RecommendedTranscript};

use k256::{
  elliptic_curve::{
    group::{ff::Field, Group},
    sec1::{Tag, ToEncodedPoint},
  },
  Scalar, ProjectivePoint,
};
use frost::{
  curve::Secp256k1,
  Participant, ThresholdKeys,
  tests::{THRESHOLD, key_gen, sign_without_caching},
};

use bitcoin_serai::{
  bitcoin::{
    hashes::Hash as HashTrait,
    blockdata::opcodes::all::OP_RETURN,
    script::{PushBytesBuf, Instruction, Instructions, Script},
    address::NetworkChecked,
    OutPoint, TxOut, Transaction, Network, Address,
  },
  wallet::{
    tweak_keys, address_payload, ReceivedOutput, Scanner, TransactionError, SignableTransaction,
  },
};

const FEE: u64 = 20;

fn is_even(key: ProjectivePoint) -> bool {
  key.to_encoded_point(true).tag() == Tag::CompressedEvenY
}

fn keys() -> (HashMap<Participant, ThresholdKeys<Secp256k1>>, ProjectivePoint) {
  let mut keys = key_gen(&mut OsRng);
  for (_, keys) in keys.iter_mut() {
    *keys = tweak_keys(keys);
  }
  let key = keys.values().next().unwrap().group_key();
  (keys, key)
}

fn sign(
  keys: &HashMap<Participant, ThresholdKeys<Secp256k1>>,
  tx: SignableTransaction,
) -> Transaction {
  let mut machines = HashMap::new();
  for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
    machines.insert(
      i,
      tx.clone()
        .multisig(keys[&i].clone(), RecommendedTranscript::new(b"bitcoin-serai Test Transaction"))
        .unwrap(),
    );
  }
  sign_without_caching(&mut OsRng, machines, &[])
}

#[test]
fn test_tweak_keys() {
  let mut even = false;
  let mut odd = false;

  // Generate keys until we get an even set and an odd set
  while !(even && odd) {
    let mut keys = key_gen(&mut OsRng).drain().next().unwrap().1;
    if is_even(keys.group_key()) {
      // Tweaking should do nothing
      assert_eq!(tweak_keys(&keys).group_key(), keys.group_key());

      even = true;
    } else {
      let tweaked = tweak_keys(&keys).group_key();
      assert_ne!(tweaked, keys.group_key());
      // Tweaking should produce an even key
      assert!(is_even(tweaked));

      // Verify it uses the smallest possible offset
      while keys.group_key().to_encoded_point(true).tag() == Tag::CompressedOddY {
        keys = keys.offset(Scalar::ONE);
      }
      assert_eq!(tweaked, keys.group_key());

      odd = true;
    }
  }
}
