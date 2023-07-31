#[cfg(test)]
mod literal {
  use std::collections::HashMap;

  use rand_core::OsRng;

  use ciphersuite::{Ciphersuite, Ristretto};

  use crate::{
    Participant, ThresholdParams,
    resharing::*,
    tests::{recover_key, frost::frost_gen},
  };

  const CONTEXT: &str = "DKG Test Resharing";

  #[test]
  fn resharing() {
    let keys = frost_gen::<_, Ristretto>(&mut OsRng);

    let first_keys = keys.values().next().unwrap().clone();
    let resharers = (1 ..= first_keys.params().t()).map(Participant).collect::<Vec<_>>();
    let mut resharer_machines = vec![];
    let mut commitments = vec![];
    for i in &resharers {
      let (machine, msg) = ResharingMachine::new(
        keys[i].clone().into(),
        resharers.clone(),
        ThresholdParams::new(2, 6, Participant::new(1).unwrap()).unwrap(),
        CONTEXT.to_string(),
      )
      .unwrap()
      .generate_coefficients(&mut OsRng);
      resharer_machines.push(machine);
      commitments.push(msg);
    }

    let mut reshareds = HashMap::new();
    let mut keys = HashMap::new();
    for i in 1 ..= 6u16 {
      let i = Participant::new(i).unwrap();
      let new_params = ThresholdParams::new(2, 6, i).unwrap();
      let (machine, key) = ResharedMachine::new(
        &mut OsRng,
        resharers.len().try_into().unwrap(),
        new_params,
        CONTEXT.to_string(),
        commitments.clone(),
      )
      .unwrap();
      reshareds.insert(i, machine);
      keys.insert(i, key);
    }

    let mut shares = vec![];
    for resharer in resharer_machines {
      shares.push(resharer.generate_secret_shares(&mut OsRng, keys.clone()).unwrap());
    }

    let mut verification_shares = None;
    let mut keys = HashMap::new();
    for i in 1 ..= 6u16 {
      let i = Participant::new(i).unwrap();
      let these_keys = reshareds
        .remove(&i)
        .unwrap()
        .accept_shares(
          &mut OsRng,
          shares.iter().map(|shares| shares[&i].clone()).collect::<Vec<_>>(),
        )
        .unwrap();

      // Verify the verification_shares are agreed upon
      if verification_shares.is_none() {
        verification_shares = Some(these_keys.verification_shares());
      }
      assert_eq!(verification_shares.as_ref().unwrap(), &these_keys.verification_shares());

      // Verify the group keys are agreed upon
      assert_eq!(these_keys.group_key(), first_keys.group_key());

      keys.insert(i, these_keys.into());
    }

    assert_eq!(Ristretto::generator() * recover_key(&keys), first_keys.group_key());
  }
}
