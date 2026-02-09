//! lilith-zero: A secure MCP Middleware.
//!
//! This library provides the core logic for the lilith-zero MCP interceptor,
//! which enforces data-at-rest and data-in-transit security policies
//! for Model Context Protocol (MCP) servers.

pub mod config;
pub mod engine;
pub mod engine_core;
pub mod mcp;
pub mod protocol;
pub mod utils;
