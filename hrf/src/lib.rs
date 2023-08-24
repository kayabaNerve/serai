#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::borrowed_box, clippy::box_collection, clippy::boxed_local)]

pub mod key_gen;
pub mod sign;
pub mod resharing;

// Seed languages
pub const LANGUAGE_ENGLISH: u8 = 1;
pub const LANGUAGE_CHINESE_SIMPLIFIED: u8 = 2;
pub const LANGUAGE_CHINESE_TRADITIONAL: u8 = 3;
pub const LANGUAGE_FRENCH: u8 = 4;
pub const LANGUAGE_ITALIAN: u8 = 5;
pub const LANGUAGE_JAPANESE: u8 = 6;
pub const LANGUAGE_KOREAN: u8 = 7;
pub const LANGUAGE_SPANISH: u8 = 8;

// Common errors
pub const UNKNOWN_ERROR: u8 = 21;
pub const INVALID_ENCODING_ERROR: u8 = 22;
pub const INVALID_PARTICIPANT_ERROR: u8 = 23;
pub const INVALID_SHARE_ERROR: u8 = 24;

// Key gen errors
pub const ZERO_PARAMETER_ERROR: u8 = 41;
pub const INVALID_THRESHOLD_ERROR: u8 = 42;
pub const INVALID_NAME_ERROR: u8 = 43;
pub const UNKNOWN_LANGUAGE_ERROR: u8 = 44;
pub const INVALID_SEED_ERROR: u8 = 45;
pub const INVALID_AMOUNT_OF_COMMITMENTS_ERROR: u8 = 46;
pub const INVALID_COMMITMENTS_ERROR: u8 = 47;
pub const INVALID_AMOUNT_OF_SHARES_ERROR: u8 = 48;

// Sign errors
pub const INVALID_OUTPUT_ERROR: u8 = 61;
pub const INVALID_ADDRESS_ERROR: u8 = 62;
pub const INVALID_NETWORK_ERROR: u8 = 63;
pub const NO_INPUTS_ERROR: u8 = 64;
pub const NO_OUTPUTS_ERROR: u8 = 65;
pub const DUST_ERROR: u8 = 66;
pub const NOT_ENOUGH_FUNDS_ERROR: u8 = 67;
pub const TOO_LARGE_TRANSACTION_ERROR: u8 = 68;
pub const WRONG_KEYS_ERROR: u8 = 69;
pub const INVALID_PREPROCESS_ERROR: u8 = 70;

// Resharing errors
pub const INVALID_PARTICIPANTS_AMOUNT_ERROR: u8 = 81;
pub const DUPLICATED_PARTICIPANT_ERROR: u8 = 82;
pub const NOT_ENOUGH_RESHARERS_ERROR: u8 = 83;
pub const INVALID_RESHARED_MSG_ERROR: u8 = 84;
pub const INVALID_RESHARER_MSG_ERROR: u8 = 85;

#[repr(C)]
pub struct StringView {
  pub ptr: *const u8,
  pub len: usize,
}
impl StringView {
  pub(crate) fn new(to_view: &str) -> StringView {
    StringView { ptr: to_view.as_ptr(), len: to_view.len() }
  }
  pub(crate) fn to_string(&self) -> Option<String> {
    let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
    String::from_utf8(slice.to_vec()).ok()
  }
}

#[repr(C)]
pub struct OwnedString {
  str_box: *mut String,
  pub ptr: *const u8,
  pub len: usize,
}
impl OwnedString {
  pub(crate) fn new(str: String) -> OwnedString {
    OwnedString { ptr: str.as_ptr(), len: str.len(), str_box: Box::into_raw(Box::new(str)) }
  }
  #[no_mangle]
  pub extern "C" fn free_owned_string(self) {
    drop(unsafe { Box::from_raw(self.str_box) });
  }
}

#[repr(C)]
pub struct CResult<T> {
  value: Option<Box<T>>,
  err: u8,
}
impl<T> CResult<T> {
  pub(crate) fn new(res: Result<T, u8>) -> Self {
    match res {
      Ok(value) => CResult { value: Some(value.into()), err: 0 },
      Err(e) => CResult { value: None, err: e },
    }
  }
}

pub struct ThresholdKeysWrapper(frost::dkg::ThresholdKeys<ciphersuite::Secp256k1>);
