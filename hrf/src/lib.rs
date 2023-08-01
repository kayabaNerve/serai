#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(clippy::missing_safety_doc)]

pub mod key_gen;
pub mod sign;

// Seed languages
pub const LANGUAGE_ENGLISH: u16 = 1;
pub const LANGUAGE_CHINESE_SIMPLIFIED: u16 = 2;
pub const LANGUAGE_CHINESE_TRADITIONAL: u16 = 3;
pub const LANGUAGE_FRENCH: u16 = 4;
pub const LANGUAGE_ITALIAN: u16 = 5;
pub const LANGUAGE_JAPANESE: u16 = 6;
pub const LANGUAGE_KOREAN: u16 = 7;
pub const LANGUAGE_SPANISH: u16 = 8;

// Common errors
pub const UNKNOWN_ERROR: u16 = 101;
pub const INVALID_ENCODING_ERROR: u16 = 102;
pub const INVALID_PARTICIPANT_ERROR: u16 = 103;
pub const INVALID_SHARE_ERROR: u16 = 104;

// Key gen errors
pub const ZERO_PARAMETER_ERROR: u16 = 201;
pub const INVALID_THRESHOLD_ERROR: u16 = 202;
pub const INVALID_NAME_ERROR: u16 = 203;
pub const UNKNOWN_LANGUAGE_ERROR: u16 = 204;
pub const INVALID_SEED_ERROR: u16 = 205;
pub const INVALID_AMOUNT_OF_COMMITMENTS_ERROR: u16 = 206;
pub const INVALID_COMMITMENTS_ERROR: u16 = 207;
pub const INVALID_AMOUNT_OF_SHARES_ERROR: u16 = 208;

// Sign errors
pub const INVALID_OUTPUT_ERROR: u16 = 301;
pub const INVALID_ADDRESS_ERROR: u16 = 302;
pub const INVALID_NETWORK_ERROR: u16 = 303;
pub const NO_INPUTS_ERROR: u16 = 304;
pub const NO_OUTPUTS_ERROR: u16 = 305;
pub const DUST_ERROR: u16 = 306;
pub const NOT_ENOUGH_FUNDS_ERROR: u16 = 307;
pub const TOO_LARGE_TRANSACTION_ERROR: u16 = 308;
pub const WRONG_KEYS_ERROR: u16 = 309;
pub const INVALID_PREPROCESS_ERROR: u16 = 310;

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
  pub extern "C" fn free(self) {
    drop(unsafe { Box::from_raw(self.str_box) });
  }
}
