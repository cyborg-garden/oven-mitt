//! ovenmitt core library. The `ovenmitt` binary is a thin dispatcher over
//! these modules; integration tests in `tests/` use them directly.
//!
//! Module map follows DEVELOPMENT.md §2. Modules arrive milestone by milestone.

#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod pattern;
