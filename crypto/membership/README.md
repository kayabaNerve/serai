# Tony (Membership of Bulletproofs -> MoB -> Mob -> Tony) Proof

This is intended to be an membership proof usable within Seraphis offering a
complete anonymity set. It's instantiated over Bulletproofs (providing a R1CS
constraint system) and has two steps:

1) Unblind. For the given input `result: Point`, subtract a known-to-the-prover
  scalar.
2) Prove existence in a merkle tree.

### Status

This is effectively guaranteed to be insecure. Its incomplete, unreviewed,
and should not be used.

### Tony-Specific Requirements

Once the full proof is formed, it must be able to have its tree depth grown.
Even with a depth of 2^32, only 4 billion outputs would be supported, which is
not something which will survive for decades on end (though it should be noted
Monero only has 61 million outputs since activating RingCT). Ideally, we have
an unbalanced Merkle tree, where the left-most element can theoretically be
proven in just O(1), yet performance is mandated to the O(n) of the right-most
element.
