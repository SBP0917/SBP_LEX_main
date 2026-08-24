#![deny(unsafe_op_in_unsafe_fn)]
#![allow(
    clippy::assigning_clones,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::too_many_lines
)]
//! Veto-only SBP-LEX V2 trusted boundary.

pub mod audit;
pub mod authority;
pub mod canonical;
pub mod decision;
pub mod digest;
pub mod dispatch;
pub mod evidence;
pub mod filed_framework;
pub mod filed_lifecycle;
pub mod hash_chain;
pub mod licence;
pub mod permit;
pub mod pre_effect;
pub mod replay;
pub mod request;
pub mod revocation;
pub mod signature;
pub mod skg;
pub mod three_p;
pub mod token;
pub mod tpm;

pub use decision::{BoundaryError, ClosedDecision, Gap};

#[cfg(test)]
mod tests;
