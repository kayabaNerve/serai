type ValidatorId = u16;

enum Step {
  Propose,
  Prevote,
  Precommit,
}

struct Block;

struct Proposal {
  height: u32,
  round: u32,
  valid_round: Option<u32>,
  proposal: Block,
}

struct Global {
  height: u32,

  round: u32,
  step: Step,
  locked: Option<(u32, Block)>,
  valid: Option<(u32, Block)>,

  decision: Vec<_>,
}

enum Data {
  Proposal(Option<u16>, Block)
  Prevote
  Precommi
}

struct Message {
  sender: ValidatorId,

  height: u32,
  round: u32,

  data: Data,
}

enum BlockError {
  // Invalid behavior entirely
  Fatal,
  // Potentially valid behavior dependent on unsynchronized state
  Temporal,
}

enum TendermintError {
  MaliciousOrTemporal(u16), // TODO: Remove when we figure this out
  Malicious(u16),
  Offline(u16),
  Temporal,
}

impl Global {
  fn new() -> Global {
    Global {
      height: 0,

      round: 0,
      step: Step::Propose,
      locked: None,
      valid: None,

      decision: vec![],
    }
  }

  fn round(&mut self, proposal: Option<Block>) {
    self.round += 1;
    self.step = Step::Propose;

    if let Some(proposal) = proposal {
      // If we already had a valid round, use its block, making the passed in block solely a flag
      // we're supposed to provide this value
      let (valid_round, proposal) = if let Some((round, proposal)) = self.valid {
        (Some(round), proposal)
      } else {
        (None, proposal)
      };

      broadcast Proposal {
        height: self.height,
        round: self.round,
        valid_round,
        proposal,
      }
    } else {
      timeout propose
    }
  }

  fn propose_fresh(&mut self, proposal: Message<Proposal>) -> Result<(), TendermintError> {
    debug_assert_eq!(self.step, Step::Propose);

    // Tendermint says on any action from the actual proposer, to step the round
    self.step = Step::Prevote;

    // If we locked a block, require it be used
    if let Some(round, block) == self.locked {
      if proposal.msg.id() != block.id() {
        Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
      }
    // Since it's a new block, check it's valid
    } else {
      valid(proposal.msg).map_err(|e| match e {
        BlockError::Fatal => TendermintError::MaliciousOrTemporal(proposal.sender),
        BlockError::Temporal => TendermintError::Temporal
      })?;
    }

    Ok(())
  }

  fn upon_proposal(&mut self, proposal: Message<Proposal>) -> Result<(), TendermintError> {
    if proposal.msg.height != self.height {
      Err(TendermintError::Temporal)?;
    }

    // Not the proposer for the specified round
    if proposal.sender != proposer(proposal.msg.height, proposal.msg.round) {
      Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
    }

    // Propose 0 (L22), Propose 1 (L28), or Propose 2 (L36)
    if proposal.msg.round == self.round {
      if proposal.msg.valid_round.is_none() {
        // Propose type 0

        // Re-proposing
        if !matches!(self.step, Step::Propose) {
          Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
        }

        let res = self.propose_fresh(proposal);
        broadcast Prevote {
          height: self.height,
          round: self.round,
          id: Some(block.id()).filter(|_| res.is_ok())
        }
        res
      } else if let Some(valid_round) = proposal.msg.valid_round {
        // Propose type 1
        if matches!(self.step, Step::Propose) {
          if prevote_consensus(self.height, valid_round, proposal.msg.block.id()) {
            Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
          }

          if !(valid_round < self.round) {
            Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
          }

          // L29 of Tendermint says to additionally check validity here. Considering 2n+1 prevoted on
          // it, it already has gone through the consensus process on validity
          broadcast Prevote {
            height: self.height,
            round: self.round,
            id: Some(proposal.msg.id()).filter(
              |id| self.locked.map(|(round, value)| (round < valid_round) || (value.id() == id)).unwrap_or(true)
            )
          }
        } else {
          // Propose type 2
          if prevote_consensus(self.height, self.round, proposal.msg.block.id()) {
            Err(TendermintError::MaliciousOrTemporal(proposal.sender))?;
          }

          if matches!(self.step, Step::Prevote) {
            self.step = Step::Precommit;
            self.locked = (self.round, proposal.msg.block);
            broadcast Precommit self.height self.round proposal.msg.block.id()
          }
          self.valid = Some((self.round, proposal.msg.block));
          Ok(())
        }
      }
    }
  }
}
