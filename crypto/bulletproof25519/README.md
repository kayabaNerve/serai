# Bulletproof25519

Bulletroof25519 refers to a Weierstrass curve whose Scalar field is equivalent
to the Ed25519 field. Accordingly, it is suitable for arithmetic circuits where
Ed25519 points are used as variables.

Full credit for the curve goes to [Liam Eagen](https://github.com/Liam-Eagen).

This library is currently extremely inefficient and only minimally tested.
It rejects deserializing torsioned points and does not expose a way to create
them. This will likely be replaced with either a scheme clearing torsion or a
prime-order encoding.

constant time and no_std.
