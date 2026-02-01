//! Sentinel: A secure MCP Middleware.
//!
//! This library provides the core logic for the Sentinel MCP interceptor,
//! which enforces data-at-rest and data-in-transit security policies
//! for Model Context Protocol (MCP) servers.

pub mod config;
pub mod constants;
pub mod core;
pub mod engine;
pub mod mcp;
pub mod utils;
pub mod protocol;
