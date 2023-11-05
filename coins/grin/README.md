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

### Key Generation

Unfortunately, Serai can not use a single multisig private key due to key
cancellation attacks. If Serai created two outputs, with the same key (serving
as the mask), one output could be used to spend the other.

While additive offsets and multiplicative products are also insecure, due to
Wagner's algorithm, an individual key may be reused up to 255 times (for
secp256k1). For a completely ordered set of uses, indexed by `i`, a key may be
used as `2**i K`. While this does trivially have conflicts in a multiset
(`2**(2i) K` == `2**i K + 2**i K`), Grin does not allow duplicated outputs
within a transaction.

Fully independent keys would also work, yet would require a O(n^2) DKG which
would reduce fault tolerance. Serai multisig's traditionally require 100%
participation to create them in order to ensure any 67% can access the multisig.
Ad-hoc key generation would require 67% of validators perform the DKG, with
shares still distributed to offline validators. In order to prevent invalid
shares from being distributed, a ZK proof would be required confirming validity.

An optimistic/fraud-proof based solution to invalid key shares is invalid as
a malicious validator who distributes invalid shares creates an output their
participation is required to spend. This limits the received outputs over the
time period we give for fraud proofs to the sum value to the stake of any
individually participating validator.

We either have to have a large upfront cost, which may be acceptable given a
sufficient Verifiable-Multi-Secret-Sharing scheme, or have an in-the-moment
O(n^2) cost of which the results would have to be propagated between validator
sets in some sufficiently secure fashion.

### Receiving Transaction Construction

The traditional flow for a Grin TX occurs with Serai taking the role of Bob.
Users would publish `raG, maG, fee` to the Serai validator set, the validator
set would order and come to consensus on it, and respond with `rbG, mbG, sb`.
This response would be accompanied with a signed statement from the validators
such that it's possible to prove a commitment which exists on Grin belongs to
the Serai validator set and the set is expected to have handled it.

## Scanning of on-chain TXs

Grin traditionally is able to determine the amount in a commitment by rewinding
the Bulletproof associated with it. That may or may not be possible in a MPC
setting. The following idea, which isn't premised on utilization of the
Bulletproof, is posited.

Grin has a circulating supply of ~120m (growing by 30m each year).

1) Only operate over whole Grin amounts. This would only leave a 2**32 search
   space (an 137.6 GB data-set, which could be reused across keys) valid for
   the next ~139 years. While this space could be further limited by setting a
   max output amount (say 10m), that'd any outputs exceeding that amount
   unrepresentable. That'd set the maximum supply of sriGRIN to that limit,
   which wouldn't be pleasant.
2) Perform 16 lookups instead of 1, shrinking the size of the lookup table to
   8.6 GB. Subtracting 1 ..= 16 * H and performing 4 halvings (shifting the
   amount down) would suffice to accomplish this.

## Burns

Upon a collection of `Burn` events, each containing `raG, maG, fee`, Serai can
create a transaction with one output per `Burn`. Each of these outputs will be
used as the inputs in the actual transaction transferring coins to the user.

Serai would execute a signing protocol to actually perform the transfer to the
user's declared key, producing `rbG, sb`. The user must come back and read
`rbG, sb` from Serai to then produce `sa` and publish their transaction
on-chain.

The Serai validator set MAY produce a distinct `sa` and steal this output.
Accordingly, when the validator set is retiring and has completed all other
actions, the following occurs:

1) For each unused `sa`, a new transaction transferring the output to the new
   multisig is created. The new multisig is expected to then recreate the `sa`
   to-be-claimed.
2) Either the commitment transferring the output to the new multisig or the
   `raG + rbG` used within the challenge for the original `saG` will appear
   on-chain.

The worst a validator set can do is not publish `sa` in a reasonable amount of
time, effectively censoring the user. If this is called out, a social
intervention could occur.

## Verifying Burns On-Chain

We can confirm a `Burn` was completed by checking a transaction exists such
that: `input_commitments - output_commitments = maG + (burnt_amount - fee)H`.

It'd be the user's requirement to specify a `maG` with no other intent
specified, letting the commitment alone be binding to intent.

## Refunds

Every transfer to Serai could include `raG, maG, fee`, enabling execution of the
above `Burn` protocol upon an on-Serai error.

## Summary

Serai would be able to interactively receive GRIN, verifiably, with:

1) Either a sufficiently performant VMSS scheme/a robust DKG which proves
   integrity of shares intended for non-participating validators
2) A way for users to trigger the signing protocol to receive on the Tributary
3) A way for users to read the results of said signing protocol

Serai would be able to interactively send GRIN, verifiably, with:

1) A way for users to read the `sa` result of the transfer protocol

We'd also require a spam proof, such as Tor's recent efforts on PoW.

## Questions

- Grin implemented a MPC Bulletproof in
  https://github.com/mimblewimble/secp256k1-zkp/pull/24. Has this had its
  cryptography audited?
- Can we replace the lookup table with the traditional amount recovery based on
  BP-rewinding strategy?
  https://tlu.tarilabs.com/protocols/mimblewimble-mb-bp-utxo#comparison-of-the-two-bulletproof-methods
  claims no.
