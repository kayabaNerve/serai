#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod key_gen;

pub const UNKNOWN_ERROR: u8 = 1;
pub const ZERO_PARAMETER_ERROR: u8 = 2;
pub const INVALID_THRESHOLD_ERROR: u8 = 3;
pub const INVALID_PARTICIPANT_ERROR: u8 = 4;
pub const INVALID_NAME_ERROR: u8 = 5;
pub const INVALID_ENCODING_ERROR: u8 = 6;
pub const UNKNOWN_LANGUAGE_ERROR: u8 = 7;
pub const INVALID_SEED_ERROR: u8 = 8;
pub const INVALID_AMOUNT_OF_COMMITMENTS_ERROR: u8 = 9;
pub const INVALID_COMMITMENTS_ERROR: u8 = 10;
pub const INVALID_AMOUNT_OF_SHARES_ERROR: u8 = 11;
pub const INVALID_SHARE_ERROR: u8 = 12;

pub const LANGUAGE_ENGLISH: u8 = 255;
pub const LANGUAGE_CHINESE_SIMPLIFIED: u8 = 254;
pub const LANGUAGE_CHINESE_TRADITIONAL: u8 = 253;
pub const LANGUAGE_FRENCH: u8 = 252;
pub const LANGUAGE_ITALIAN: u8 = 251;
pub const LANGUAGE_JAPANESE: u8 = 250;
pub const LANGUAGE_KOREAN: u8 = 249;
pub const LANGUAGE_SPANISH: u8 = 248;
