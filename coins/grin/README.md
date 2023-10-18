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

Please note masks are effectively private keys, and this document refers to them
as such.

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

### Single-interaction Variant

This can be performed with just a single interaction as follows:

1) Users create an output to an independent private key, which they intend to
   transfer to Serai.
2) Users perform a Dealer KG of the output's private key to the Serai validator
   set.
3) The Serai validator set receives the threshold shares of the dealer key
   generation protocol *and* the InInstruction for the transaction. They then
   transfer the output to their own key. If they do not do so in a timely
   manner, the user can simply spend the output back to themselves.

Note the validator set would be able to steal coins without identifiability.

### Interactive Variant

The traditional flow for a Grin TX occurs with Serai taking the role of Bob.
Users would receive `rbG, sb`, and set `mbG` to `K`, Serai's multisig's key.

Compared to the prior variant, this would require users be able to extract the
signature from Serai's tributary.

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
   of one, yet we can shrink the size of the lookup table by a factor of 16
   (from 8.6 GB to 537 MB). The suggested bucketing algorithm is the bottom bits
   of the amount, leaving us only to recover the top bytes.

## Burns

At some point, users specify an 'address' to send the underlying GRIN to as they
burn their sriGRIN.

### Serai being Bob

1) Burns would take the role of Alice, providing `raG, maG, indidivual_fee`.
2) Serai would create `rb` with a DKG.
3) Users would publish signatures for all possible combinations of Burns which
   are actually moved forward with, assuming their own participation. This has
   exponential complexity, mandating a low-amount of outputs per batch.
4) Serai would note the users who responded in time and issue a signature using
   a robust signing protocol. The users who don't respond in time would be
   refunded (by inclusion of an `InInstruction` in the `Batch` for the block
   with the outputs for the other users).

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

A malicious multisig would be able to steal these outputs by producing a
distinct `sb` before the user completes the signature themselves (one
complimentary to the malicious attacker's 'Alice').

### Serai being Alice

Like the prior protocol, upon a `Burn` event containing
`rbG, mbG, fee`, Serai would create outputs which are 1:1 with the necessary
`Burn`s. Then, Serai would execute a DKG (an O(n^2) operation) to obtain the
nonce it'll use to transfer those outputs (`raG`).

A user would read this nonce and then provide `sb`.

Serai would execute a robust signing protocol using the nonce from the prior
DKG.

This would be verifiable. Unfortunately, this isn't guaranteed to terminate
UNLESS the user is refunded sriGRIN if their response doesn't occur in a timely
manner.

A malicious multisig could lie and claim they didn't receive a response if a
timely manner, yet doing so would solely be a censorship attack. No actual
theft could occur without leading to slash, letting social consensus handle the
issue. We would need to ensure the sriGRIN refund doesn't error due to capacity
limits however.

## Verifying Burns On-Chain

We can confirm a `Burn` was completed by checking `mbG + (burnt_amount - fee)H`
appears on-chain. It'd be the user's requirement to specify a `mbG` with no
other intent specified, letting the commitment alone be binding to intent.

With the non-exponential-as-Bob scheme proposed for issuing `Burn`s, we can't
guarantee a `Burn` to an external party appears on-chain in the first place.
We'd have to confirm some degree of data-availability for `sb` and then call it
a day.

## Refunds

It'd likely be best to not support refunds on error, forcing refunds in the form
of sriGRIN. If the network's utilization of allocated stake is at capacity
however, we'd be unable to mint sriGRIN for refund purposes. This forces UIs to
check in advance to prevent loss of funds due to errors from being at capacity.

## Summary

Serai should be able to interactively receive GRIN, verifiably, with:

1) A way for users to trigger the signing protocol to receive on the Tributary
2) A way for users to read the results of said signing protocol

Serai should be able to interactively send GRIN, verifiably, with:

1) A robust signing protocol, incurring a O(n^2) execution cost
2) A way for users to publish their signature shares onto Serai

We'd also require a spam proof, such as Tor's recent efforts on PoW.

## Questions

- Are these schemes impacted by Wagner's at all? Should users also use a
  binomial nonce?
- Is there a better solution to on-chain scanning, one which doesn't require a
  half GB lookup table?
