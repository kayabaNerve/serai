use core::{ops::Deref, fmt};
use std::io::{self, Read, Write};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite,
};

use schnorr::SchnorrSignature;

use crate::{Participant, DkgError, ThresholdParams, encryption::ReadWrite};

pub type ReshareError = DkgError<()>;

#[allow(non_snake_case)]
pub(crate) fn challenge<C: Ciphersuite>(context: &str, R: &[u8], Am: &[u8]) -> C::F {
  let mut transcript = RecommendedTranscript::new(b"DKG FROST v0.2");
  transcript.domain_separate(b"schnorr_proof_of_knowledge");
  transcript.append_message(b"context", context.as_bytes());
  transcript.append_message(b"nonce", R);
  transcript.append_message(b"commitments", Am);
  C::hash_to_F(b"DKG-FROST-proof_of_knowledge-0", &transcript.challenge(b"schnorr"))
}

/// The commitments message, intended to be broadcast to all other parties.
///
/// Every participant should only provide one set of commitments to all parties. If any
/// participant sends multiple sets of commitments, they are faulty and should be presumed
/// malicious. As this library does not handle networking, it is unable to detect if any
/// participant is so faulty. That responsibility lies with the caller.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Commitments<C: Ciphersuite> {
  pub(crate) commitments: Vec<C::G>,
  pub(crate) cached_msg: Vec<u8>,
  pub(crate) sig: SchnorrSignature<C>,
}

impl<C: Ciphersuite> ReadWrite for Commitments<C> {
  fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
    let mut commitments = Vec::with_capacity(params.t().into());
    let mut cached_msg = vec![];

    #[allow(non_snake_case)]
    let mut read_G = || -> io::Result<C::G> {
      let mut buf = <C::G as GroupEncoding>::Repr::default();
      reader.read_exact(buf.as_mut())?;
      let point = C::read_G(&mut buf.as_ref())?;
      cached_msg.extend(buf.as_ref());
      Ok(point)
    };

    for _ in 0 .. params.t() {
      commitments.push(read_G()?);
    }

    Ok(Commitments { commitments, cached_msg, sig: SchnorrSignature::read(reader)? })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.cached_msg)?;
    self.sig.write(writer)
  }
}

pub(crate) fn polynomial<F: PrimeField + Zeroize>(
  coefficients: &[Zeroizing<F>],
  l: Participant,
) -> Zeroizing<F> {
  let l = F::from(u64::from(u16::from(l)));
  // This should never be reached since Participant is explicitly non-zero
  assert!(l != F::ZERO, "zero participant passed to polynomial");
  let mut share = Zeroizing::new(F::ZERO);
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    *share += coefficient.deref();
    if idx != (coefficients.len() - 1) {
      *share *= l;
    }
  }
  share
}

/// The secret share message, to be sent to the party it's intended for over an authenticated
/// channel.
///
/// If any participant sends multiple secret shares to another participant, they are faulty.
// This should presumably be written as SecretShare(Zeroizing<F::Repr>).
// It's unfortunately not possible as F::Repr doesn't have Zeroize as a bound.
// The encryption system also explicitly uses Zeroizing<M> so it can ensure anything being
// encrypted is within Zeroizing. Accordingly, internally having Zeroizing would be redundant.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretShare<F: PrimeField>(pub(crate) F::Repr);
impl<F: PrimeField> AsRef<[u8]> for SecretShare<F> {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl<F: PrimeField> AsMut<[u8]> for SecretShare<F> {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}
impl<F: PrimeField> fmt::Debug for SecretShare<F> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("SecretShare").finish_non_exhaustive()
  }
}
impl<F: PrimeField> Zeroize for SecretShare<F> {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}
// Still manually implement ZeroizeOnDrop to ensure these don't stick around.
// We could replace Zeroizing<M> with a bound M: ZeroizeOnDrop.
// Doing so would potentially fail to highlight the expected behavior with these and remove a layer
// of depth.
impl<F: PrimeField> Drop for SecretShare<F> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<F: PrimeField> ZeroizeOnDrop for SecretShare<F> {}

impl<F: PrimeField> ReadWrite for SecretShare<F> {
  fn read<R: Read>(reader: &mut R, _: ThresholdParams) -> io::Result<Self> {
    let mut repr = F::Repr::default();
    reader.read_exact(repr.as_mut())?;
    Ok(SecretShare(repr))
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.as_ref())
  }
}
