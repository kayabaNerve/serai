#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub use std::io::*;

#[cfg(not(feature = "std"))]
mod shims;
#[cfg(not(feature = "std"))]
pub use shims::*;
