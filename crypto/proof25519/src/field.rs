use zeroize::Zeroize;

use crypto_bigint::{U512, U1024};

use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) U512);

// 694752535423897172541425910052127447118617369604688205440845127806694419544771
pub const MODULUS: FieldElement = FieldElement(U512::from_be_hex(concat!(
  "00000000000000000000000000000000000000000000000000000000000000",
  "05fffffffffffffffffffffffffffffffd0dc6212cfee590f9f26acf3b81df3ac3"
)));

const WIDE_MODULUS: U1024 = U1024::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000000000",
  "05fffffffffffffffffffffffffffffffd0dc6212cfee590f9f26acf3b81df3ac3"
));

field!(FieldElement, MODULUS, WIDE_MODULUS, 259);
