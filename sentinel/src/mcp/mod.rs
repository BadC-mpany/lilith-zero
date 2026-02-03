//! Model Context Protocol (MCP) implementation.
//!
//! This module handles the protocol-specific logic, including transport,
//! process management, and the core middleware server.

pub mod process;

pub mod server;
pub mod transport;
pub mod pipeline;
pub mod codec;
pub mod sandbox;

