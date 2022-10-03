#![allow(non_snake_case)]

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use multiexp::{multiexp, BatchVerifier};
use bulletproof25519::{scalar::Scalar, point::Point};

mod scalar_vector;
use scalar_vector::*;

mod core;
use crate::core::*;

pub struct Commitment {
  mask: Scalar,
  amount: u64,
}

impl Commitment {
  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  pub fn calculate(&self) -> Point {
    (Point::generator() * self.mask) + (*H * Scalar::from(self.amount))
  }
}

// d[j*N+i] = z**(2*(j+1)) * 2**i
fn d(z: Scalar, M: usize, MN: usize) -> (ScalarVector, ScalarVector) {
  let zpow = ScalarVector::even_powers(z, 2 * M);
  let mut d = vec![Scalar::zero(); MN];
  for j in 0 .. M {
    for i in 0 .. N {
      d[(j * N) + i] = zpow[j] * TWO_N[i];
    }
  }
  (zpow, ScalarVector(d))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BulletproofsPlus {
  pub(crate) A: Point,
  pub(crate) A1: Point,
  pub(crate) B: Point,
  pub(crate) r1: Scalar,
  pub(crate) s1: Scalar,
  pub(crate) d1: Scalar,
  pub(crate) L: Vec<Point>,
  pub(crate) R: Vec<Point>,
}

impl BulletproofsPlus {
  pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitments: &[Commitment],
  ) -> BulletproofsPlus {
    let (logMN, M, MN) = MN(commitments.len());

    let (aL, aR) = bit_decompose(commitments);
    let mut cache =
      hash_commitments(&commitments.iter().map(Commitment::calculate).collect::<Vec<_>>());
    let (mut alpha1, A) = alpha_rho(&mut *rng, &aL, &aR);

    let y = hash_cache(&mut cache, &[A.to_bytes()]);
    let mut cache = hash_to_scalar(&y.to_repr());
    let z = cache;

    let (zpow, d) = d(z, M, MN);

    let aL1 = aL - z;

    let ypow = ScalarVector::powers(y, MN + 2);
    let mut y_for_d = ScalarVector(ypow.0[1 ..= MN].to_vec());
    y_for_d.0.reverse();
    let aR1 = (aR + z) + (y_for_d * d);

    for (j, gamma) in commitments.iter().map(|c| c.mask).enumerate() {
      alpha1 += zpow[j] * ypow[MN + 1] * gamma;
    }

    let mut a = aL1;
    let mut b = aR1;

    let yinv = y.invert().unwrap();
    let yinvpow = ScalarVector::powers(yinv, MN);

    let mut G_proof = generators().G[.. a.len()].to_vec();
    let mut H_proof = generators().H[.. a.len()].to_vec();

    let mut L = Vec::with_capacity(logMN);
    let mut R = Vec::with_capacity(logMN);

    while a.len() != 1 {
      let (aL, aR) = a.split();
      let (bL, bR) = b.split();

      let cL = weighted_inner_product(&aL, &bR, y);
      let cR = weighted_inner_product(&(&aR * ypow[aR.len()]), &bL, y);

      let (mut dL, mut dR) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));

      let (G_L, G_R) = G_proof.split_at(aL.len());
      let (H_L, H_R) = H_proof.split_at(aL.len());

      let mut L_i = LR_statements(&(&aL * yinvpow[aL.len()]), G_R, &bR, H_L, cL, *H);
      L_i.push((dL, Point::generator()));
      let L_i = multiexp(&L_i);
      L.push(L_i);

      let mut R_i = LR_statements(&(&aR * ypow[aR.len()]), G_L, &bL, H_R, cR, *H);
      R_i.push((dR, Point::generator()));
      let R_i = multiexp(&R_i);
      R.push(R_i);

      let w = hash_cache(&mut cache, &[L_i.to_bytes(), R_i.to_bytes()]);
      let winv = w.invert().unwrap();

      G_proof = hadamard_fold(G_L, G_R, winv, w * yinvpow[aL.len()]);
      H_proof = hadamard_fold(H_L, H_R, w, winv);

      a = (&aL * w) + (aR * (winv * ypow[aL.len()]));
      b = (bL * winv) + (bR * w);

      alpha1 += (dL * (w * w)) + (dR * (winv * winv));

      dL.zeroize();
      dR.zeroize();
    }

    let mut r = Scalar::random(&mut *rng);
    let mut s = Scalar::random(&mut *rng);
    let mut d = Scalar::random(&mut *rng);
    let mut eta = Scalar::random(rng);

    let A1 = multiexp(&[
      (r, G_proof[0]),
      (s, H_proof[0]),
      (d, Point::generator()),
      ((r * y * b[0]) + (s * y * a[0]), *H),
    ]);
    let B = multiexp(&[(r * y * s, *H), (eta, Point::generator())]);
    let e = hash_cache(&mut cache, &[A1.to_bytes(), B.to_bytes()]);

    let r1 = (a[0] * e) + r;
    r.zeroize();
    let s1 = (b[0] * e) + s;
    s.zeroize();
    let d1 = ((d * e) + eta) + (alpha1 * (e * e));
    d.zeroize();
    eta.zeroize();
    alpha1.zeroize();

    BulletproofsPlus { A, A1, B, r1, s1, d1, L, R }
  }

  #[must_use]
  fn verify_core<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, Point>,
    id: ID,
    commitments: &[Point],
  ) -> bool {
    // Verify commitments are valid
    if commitments.is_empty() || (commitments.len() > MAX_M) {
      return false;
    }

    // Verify L and R are properly sized
    if self.L.len() != self.R.len() {
      return false;
    }

    let (logMN, M, MN) = MN(commitments.len());
    if self.L.len() != logMN {
      return false;
    }

    // Rebuild all challenges
    let mut cache = hash_commitments(commitments);
    let y = hash_cache(&mut cache, &[self.A.to_bytes()]);
    let yinv = y.invert().unwrap();
    let z = hash_to_scalar(&y.to_repr());
    cache = z;

    let mut w = Vec::with_capacity(logMN);
    let mut winv = Vec::with_capacity(logMN);
    for (L, R) in self.L.iter().zip(&self.R) {
      w.push(hash_cache(&mut cache, &[L.to_bytes(), R.to_bytes()]));
      winv.push(cache.invert().unwrap());
    }

    let e = hash_cache(&mut cache, &[self.A1.to_bytes(), self.B.to_bytes()]);

    // Verify it
    let mut proof = Vec::with_capacity(logMN + 5 + (2 * (MN + logMN)));

    let mut yMN = y;
    for _ in 0 .. logMN {
      yMN *= yMN;
    }
    let yMNy = yMN * y;

    let (zpow, d) = d(z, M, MN);
    let zsq = zpow[0];

    let esq = e * e;
    let minus_esq = -esq;
    let commitment_weight = minus_esq * yMNy;
    for (i, commitment) in commitments.iter().enumerate() {
      proof.push((commitment_weight * zpow[i], *commitment));
    }

    // Invert B, instead of the Scalar, as the latter is only 2x as expensive yet enables reduction
    // to a single addition under vartime for the first BP verified in the batch, which is expected
    // to be much more significant
    proof.push((Scalar::one(), -self.B));
    proof.push((-e, self.A1));
    proof.push((minus_esq, self.A));
    proof.push((self.d1, Point::generator()));

    let d_sum = zpow.sum() * Scalar::from(u64::MAX);
    let y_sum = weighted_powers(y, MN).sum();
    proof.push(((self.r1 * y * self.s1) + (esq * ((yMNy * z * d_sum) + ((zsq - z) * y_sum))), *H));

    let w_cache = challenge_products(&w, &winv);

    let mut e_r1_y = e * self.r1;
    let e_s1 = e * self.s1;
    let esq_z = esq * z;
    let minus_esq_z = -esq_z;
    let mut minus_esq_y = minus_esq * yMN;

    for i in 0 .. MN {
      proof.push((e_r1_y * w_cache[i] + esq_z, generators().G[i]));
      proof.push((
        (e_s1 * w_cache[(!i) & (MN - 1)]) + minus_esq_z + (minus_esq_y * d[i]),
        generators().H[i],
      ));

      e_r1_y *= yinv;
      minus_esq_y *= yinv;
    }

    for i in 0 .. logMN {
      proof.push((minus_esq * w[i] * w[i], self.L[i]));
      proof.push((minus_esq * winv[i] * winv[i], self.R[i]));
    }

    verifier.queue(rng, id, proof);
    true
  }

  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(&self, rng: &mut R, commitments: &[Point]) -> bool {
    let mut verifier = BatchVerifier::new(1);
    if self.verify_core(rng, &mut verifier, (), commitments) {
      verifier.verify_vartime()
    } else {
      false
    }
  }

  #[must_use]
  pub fn batch_verify<ID: Copy + Zeroize, R: RngCore + CryptoRng>(
    &self,
    rng: &mut R,
    verifier: &mut BatchVerifier<ID, Point>,
    id: ID,
    commitments: &[Point],
  ) -> bool {
    self.verify_core(rng, verifier, id, commitments)
  }
}
