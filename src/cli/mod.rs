//! Operator CLI subcommands. Each module exposes one function per subcommand
//! that returns the process exit code; `main.rs` only dispatches.

pub mod audit;
pub mod config;
pub mod credential;
