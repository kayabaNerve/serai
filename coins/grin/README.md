# Grin

Grin TXs are interactive, with the following flow:

1) Alice creates a TXs with inputs and a change output. `ma` is the sum of the
   inputs' masks minus the change output's. Alice selects a nonce `ra` and sends
   `raG, maG, fee` to Bob (we always assume `lock_height` to be 0).

2) Bob selects a nonce `rb` and a mask `mb`. They add their output and produce a
   signature `sb` over the challenge
   `H(fee | lock_height | raG + rbG | maG + mbG)`, with `mb` as the effective
   private key. Bob sends `rbG, mbG, sb` to Alice.

3) Alice verifies `sb`, can produce and add `sa`, and then publish the
   transaction on-chain.

This creates several difficulties when discussing an integration. To discuss the
traditional Serai flow:

1) A transaction to Serai's multisig appears on the external network.
2) Serai scans it and reads the arbitrary data associated with it (OP_RETURN,
   an event, TX extra). This is parsed into an `InInstruction`.
3) The Serai validator set obtains consensus within itself over the block's
   existence. Once a supermajority of the set acknowledges the block, they
   sign a `Batch` reporting the block hash and relevant data to `Serai`.
4) Serai eventually produces a `Burn` event, specifying an address out.
5) Inputs are added to the scheduler upon `Batch` events, and expected outputs
   are added upon `Burn` events. Serai provides a complete ordering over the
   scheduler accordingly as is needed to ensure verifiability.
6) Upon a `Batch`/`Burn` event, the validator set comes to consensus over the
   containing Serai block. Then, the processor determines which TXs it can make
   at that time and reports the list of signing protocols to the coordinator.
   With that, the execution of all signing protocols begin.
7) Completions of signing protocols are reported by their transaction hash to
   the Tributary. Processors are informed of these claimed completions by their
   Coordinator and check the completing transaction hash actually completed the
   intent. The ability to check a specific intent was completed based on
   on-chain transactions is critical.

Several components of this are immediately flaggable as incompatible, creating
the requirements for alternate solutions.

## Creation of TXs in which we receive coins

We need to actively participate in such TXs for them to even appear on-chain.

This can be successfully performed as follows:
1) Users create an output to an independent private key, which they intend to
   transfer to Serai.
2) Users perform a Dealer KG of the output's private key to the Serai validator
   set.
3) The Serai validator set receives the threshold shares of the dealer key
   generation protocol *and* the InInstruction for the transaction. They then
   transfer the output to their own key. If they do not do so in a timely
   manner, the user can simply spend the output back to themselves.

## Scanning of on-chain TXs

The first question is how does Grin, traditionally, scan on-chain transactions.
They may have a solution present here voiding the following commentary. Without
any actual knowledge of how Grin wallets have been built, the following idea is
posited.

If we consistently use the key `K` to receive coins, we can identify which
outputs (commitments) belong to us. We couldn't identify their amount however.
Grin, with a circulating supply of ~150m could have the following solution
adapted:

1) Only receive whole Grin amounts. This would only leave a 2**28 search space
   (an 8.6 GB data-set, which could be reused across multisigs).
2) Don't receive to `K`. Instead, receive to `K+b`, where `b` is some bucket
   determinant. If we define 16 buckets, we'd have to perform 16 lookups instead
   of one, yet we can shrink the size of the lookup table by 16 (from 8.6 GB to
   537 MB). The suggested bucketing algorithm is the bottom bits of the amount,
   leaving us only to recover the top bytes.

## Burns

At some point, users specify an 'address' to send the underlying GRIN to as they
burn their sriGRIN.

### Serai being Alice (minimally-interactive)

If, on creation of Serai's own outputs, Serai *pre-selects* its nonce
(requiring a DKG, a O(n^2) operation, in order to be robust), then the user can
select `fee` and immediately provide `rbG, mbG, sb`. This would let Serai
execute a robust signing protocol, publish the transaction, and with it, remove
interactivity requirements when sending out.

Unfortunately, this would require being able to lock usage of an input *and*
would only let us satisfy one output with an input at a time. In order to
prevent a backlog from forming, Serai needs to be able to execute outputs in
*logarithmic time*.

### Serai being Bob

The next idea would be to define an extended protocol.

1) Burns would take the role of Alice, providing `raG, maG, indidivual_fee`.
2) Serai would create `rb` with a DKG.
3) Users would publish signatures for all possible combinations of Burns which
   are actually moved forward with, assuming their own participation. This has
   exponential complexity, mandating a low-amount of outputs per batch.
4) Serai would note the users who responded in time and issue a signature using
   a robust signing protocol. The users who don't respond in time would be
   refunded (by inclusion of an `InInstruction` in the `Batch` for the block
   with the outputs for the other users).

This may be viable.

### Serai being Bob (non-exponential)

Upon a collection of `Burn` events, Serai can create a transaction with all the
outputs needed to fulfill the `Burn`s (one output per `Burn`). By
logarithmically scheduling the outputs used to fulfill `Burn`s, we can linearly
fulfill the `Burn`s at the end *with a total runtime which is logarithmic*
(despite a superlinear amount of signing protocols).

Once Serai has dedicated outputs for each `Burn`, if the `Burn` event's address
is `raG, maG, fee`, then Serai can produce `sb` signatures for its eventual
outputs. Then, these must be communicated to the user, who has to complete the
signature and publish the TX themselves.

A malicious multisig would be able to steal these outputs. I cannot personally
comment if this would be detectable.

## Verifying Burns On-Chain

We can confirm a `Burn` was completed by checking `mbG + (burnt_amount - fee)H`
appears on-chain. It'd be the user's requirement to specify a `mbG` with no
other intent specified, letting the commitment alone be binding to intent.

With the non-exponential-as-Bob scheme proposed for issuing `Burn`s, we can't
guarantee a `Burn` to an external party appears on-chain in the first place.
We'd have to confirm some degree of data-availability for `sb` and then call it
a day.

## Multisig Rotation

TODO

## Summary

If we add a data pipeline, with a spam proof such as Tor's recent efforts on
PoW, for validators to receive off-chain data and act on it, we can get
transferred outputs with solely one message passed from sender to receiver. We
can also use a non-robust (and O(n)) signing protocol to take ownership of said
output.

For `Burn`s out, we're able to create dedicated outputs per-Burn and use a
non-robust signing protocol to produce `sb` signature shares. This would let
users claim their received outputs, yet the most verification Serai could do is
that a `sb` signature share was produced. It'd be unable to verify the user's
successful claiming, as they user may never claim the output, and it *may* be
unable to detect if after the `sb` signature share is produced, the validator
set turns malicious and steals the output. More research is needed here.

A better solution to on-chain scanning (which doesn't require a half GB lookup
table) is desirable.

Review in general of if this is sane, of what improvements can be made, and if
something is wrong would be appreciated.
