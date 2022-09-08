# Minimal Proof25519

Proof25519 refers to a Weierstrass curve whose Scalar field is equivalent to the
Ed25519 FieldElement field. Accordingly, it is usable for arithmetic circuits
where Ed25519 points are used as variables. This is not the legitimate name of
the curve, yet solely a placeholder.

Inefficient, barebones implementation of Proof25519 bound to the ff/group API,
rejecting torsion to achieve a PrimeGroup definition. This likely should not be
used and was only done as a proof of concept. It is minimally tested, yet should
be correct for what it has. Multiple functions remain unimplemented.

constant time and no_std.
