#![allow(non_snake_case)]

use core::marker::PhantomData;

use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;
use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite,
};

use ecip::Ecip;
use bulletproofs_plus::{
  arithmetic_circuit::*,
  gadgets::{
    elliptic_curve::{Trit, DLogTable, EmbeddedCurveOperations, scalar_to_trits},
    set_membership::assert_variable_in_set_gadget,
  },
};

pub mod pedersen_hash;
pub mod permissible;
use permissible::Permissible;
pub mod tree;
use tree::*;

#[cfg(test)]
pub mod tests;

pub trait CurveCycle: Clone + Copy + PartialEq + Eq + core::fmt::Debug {
  type C1: Ecip<FieldElement = <Self::C2 as Ciphersuite>::F>
    + EmbeddedCurveOperations<Embedded = Self::C2>;
  type C2: Ecip<FieldElement = <Self::C1 as Ciphersuite>::F>
    + EmbeddedCurveOperations<Embedded = Self::C1>;

  fn c1_coords(
    point: <Self::C1 as Ciphersuite>::G,
  ) -> (<Self::C2 as Ciphersuite>::F, <Self::C2 as Ciphersuite>::F);
  fn c2_coords(
    point: <Self::C2 as Ciphersuite>::G,
  ) -> (<Self::C1 as Ciphersuite>::F, <Self::C1 as Ciphersuite>::F);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FlipCurveCycle<C: CurveCycle>(PhantomData<C>);
impl<C: CurveCycle> CurveCycle for FlipCurveCycle<C> {
  type C1 = C::C2;
  type C2 = C::C1;

  fn c1_coords(
    point: <Self::C1 as Ciphersuite>::G,
  ) -> (<Self::C2 as Ciphersuite>::F, <Self::C2 as Ciphersuite>::F) {
    C::c2_coords(point)
  }
  fn c2_coords(
    point: <Self::C2 as Ciphersuite>::G,
  ) -> (<Self::C1 as Ciphersuite>::F, <Self::C1 as Ciphersuite>::F) {
    C::c1_coords(point)
  }
}

pub fn new_blind<R: RngCore + CryptoRng, C1: Ciphersuite, C2: Ciphersuite>(
  rng: &mut R,
  mutual_trits: usize,
  offset: u64,
) -> (C1::F, C2::F) {
  // Generate a candidate within the mutual trit capacity
  let res = loop {
    let candidate = C1::F::random(&mut *rng);
    let trits = scalar_to_trits::<C1>(candidate + C1::F::from(offset));
    if trits.len() <= mutual_trits {
      // TODO: Support divisors when we have an odd amount of points and remove this
      if (trits.iter().filter(|trit| **trit != Trit::Zero).count() % 2) != 1 {
        continue;
      }
      break candidate;
    }
  };

  let mut c2_repr = <C2::F as PrimeField>::Repr::default();
  c2_repr.as_mut().copy_from_slice(res.to_repr().as_ref());
  (res, C2::F::from_repr(c2_repr).unwrap())
}

pub fn layer_gadget<R: RngCore + CryptoRng, T: Transcript, C: CurveCycle>(
  rng: &mut R,
  circuit: &mut Circuit<T, C::C2>,
  permissible: &Permissible<C::C1>,
  H: &DLogTable<C::C1>,
  pedersen_generators: &[<C::C2 as Ciphersuite>::G],
  blinded_point: <C::C1 as Ciphersuite>::G,
  blind: Option<<C::C1 as Ciphersuite>::F>,
  permissibility_offset: u64,
  elements: Vec<Option<<C::C2 as Ciphersuite>::F>>,
  last: bool,
) -> (Option<<C::C2 as Ciphersuite>::F>, <C::C2 as Ciphersuite>::G) {
  // Unblind the point
  let unblinded = {
    let (blind_x, blind_y) = if let Some(blind) = blind {
      let coords = C::c1_coords(H.generator() * blind);
      (Some(coords.0), Some(coords.1))
    } else {
      (None, None)
    };
    let blind_x = circuit.add_secret_input(blind_x);
    let blind_y = circuit.add_secret_input(blind_y);
    let blind_var = C::C2::constrain_on_curve(circuit, blind_x, blind_y);

    // Prove we know the DLog of the point we're unblinding by to prevent unblinding by arbitrary
    // points
    C::C2::dlog_pok(&mut *rng, circuit, H, blind_var, blind);

    // Perform the addition
    C::C2::incomplete_add_constant(circuit, blind_var, blinded_point)
  };

  // Make sure the point is permissible
  permissible.gadget(circuit, unblinded.y());

  // Create the branch hash
  {
    // Add the elements in this hash
    let mut x_coords = vec![];
    for elem in elements.clone() {
      x_coords.push(circuit.add_secret_input(elem));
    }

    let x_coords = {
      let mut prods = vec![];
      let mut i = 0;
      while i < x_coords.len() {
        let (l, r, _) =
          circuit.product(x_coords[i], x_coords.get(i + 1).copied().unwrap_or(x_coords[i])).0;
        prods.push(l);
        prods.push(r);
        i += 2;
      }
      prods.truncate(x_coords.len());
      prods
    };

    // Ensure the unblinded point's x coordinate is actually present in the hash
    assert_variable_in_set_gadget(
      circuit,
      circuit.variable_to_product(unblinded.x()).unwrap(),
      &x_coords,
    );

    // Bind these to the branch hash
    let commitment = circuit.allocate_vector_commitment();
    assert_eq!(pedersen_generators.len(), elements.len());
    for i in 0 .. elements.len() {
      circuit.bind(commitment, x_coords[i], Some(pedersen_generators[i]));
    }

    let blind = Some(if last {
      // If this is the last hash, just use the final permissibility offset
      -<C::C2 as Ciphersuite>::F::from(permissibility_offset)
    } else {
      new_blind::<_, C::C1, C::C2>(rng, H.trits(), permissibility_offset).1
    })
    .filter(|_| circuit.prover());
    (
      // Add the permissibility offset so the 'unblinded' Pedersen hash has the blind needed to be
      // permissible
      // TODO: Adding this offset may make the blind no longer mutual
      blind.map(|blind| blind + <C::C2 as Ciphersuite>::F::from(permissibility_offset)),
      circuit.finalize_commitment(commitment, blind.map(|blind| -blind)),
    )
  }
}

pub fn membership_gadget<R: RngCore + CryptoRng, T: Transcript, C: CurveCycle>(
  rng: &mut R,
  circuit_c1: &mut Circuit<T, C::C1>,
  circuit_c2: &mut Circuit<T, C::C2>,
  tree: &Tree<C>,
  blinded_point: <C::C1 as Ciphersuite>::G,
  blind: Option<<C::C1 as Ciphersuite>::F>,
) {
  let mut membership =
    blind.map(|blind| tree.membership(blinded_point + (circuit_c1.h() * blind)).unwrap());

  let mut blinded_point = Hash::Even(blinded_point);
  let mut even_blind = None;
  let mut odd_blind = Some(blind);

  // TODO: Create these out of gadget (inside tree?)
  let c1_h = DLogTable::<C::C1>::new(circuit_c1.h());
  let c2_h = DLogTable::<C::C2>::new(circuit_c2.h());

  for i in 1 ..= tree.depth() {
    if (i % 2) == 1 {
      let Hash::Even(this_blinded_point) = blinded_point else {
        panic!("blinded_point was odd at odd layer")
      };

      let (permissibility_offset, elems) = if let Some(membership) = membership.as_mut() {
        let mut elems = vec![];
        let (permissibility_offset, points) = membership.remove(0);
        for point in points {
          let Hash::Even(point) = point else { panic!("odd layer had odd children") };
          elems.push(Some(C::c1_coords(point).0));
        }
        (permissibility_offset, elems)
      } else {
        (0, vec![None; tree.width()])
      };

      let (blind, point) = layer_gadget::<_, _, C>(
        rng,
        circuit_c2,
        tree.permissible_c1(),
        &c1_h,
        tree.odd_generators(i).unwrap(),
        this_blinded_point,
        odd_blind.take().unwrap(),
        permissibility_offset,
        elems,
        i == tree.depth(),
      );

      blinded_point = Hash::Odd(point);
      even_blind = Some(blind);
    } else {
      let Hash::Odd(this_blinded_point) = blinded_point else {
        panic!("blinded_point was even at even layer")
      };

      let (permissibility_offset, elems) = if let Some(membership) = membership.as_mut() {
        let mut elems = vec![];
        let (permissibility_offset, points) = membership.remove(0);
        for point in points {
          let Hash::Odd(point) = point else { panic!("even layer had even children") };
          elems.push(Some(C::c2_coords(point).0));
        }
        (permissibility_offset, elems)
      } else {
        (0, vec![None; tree.width()])
      };

      let (blind, point) = layer_gadget::<_, _, FlipCurveCycle<C>>(
        rng,
        circuit_c1,
        tree.permissible_c2(),
        &c2_h,
        tree.even_generators(i).unwrap(),
        this_blinded_point,
        even_blind.take().unwrap(),
        permissibility_offset,
        elems,
        i == tree.depth(),
      );

      blinded_point = Hash::Even(point);
      odd_blind = Some(blind);
    }
  }

  // TODO: We don't need proofs that the tree root VC is well formed. We can just add it ourselves
  assert_eq!(blinded_point, tree.root());
}
