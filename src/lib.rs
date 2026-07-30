// Anything written to stdout outside of the rmcp transport corrupts the MCP
// JSON-RPC framing — the client silently disconnects. These deny lints make
// the build fail before that happens.
#![deny(clippy::print_stdout, clippy::print_stderr)]
#![doc = include_str!("../README.md")]
//!
//! # Library API
//!
//! The shipped artifact is the `fast-mcp-ssh` binary. These modules are public
//! so the internals are documented and reusable, not because they are a stable
//! surface: they can change in any release without a major version bump.

pub mod audit;
pub mod config;
pub mod errors;
pub mod forward;
pub mod guards;
pub mod known_hosts;
pub mod output;
pub mod server;
pub mod session;
pub mod sftp;
pub mod ssh_config;
pub mod tail;
pub mod tools;
