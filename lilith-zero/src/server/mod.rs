// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Webhook server for the Copilot Studio external security provider API.
//!
//! Enable with `--features webhook` at build time:
//! ```bash
//! cargo build --features webhook
//! lilith-zero serve --bind 0.0.0.0:8080 --policy policy.yaml
//! ```
//!
//! # Modules
//! - [`auth`] — JWT authentication (no-auth / shared-secret / Entra ID).
//! - [`copilot_studio`] — Request/response types and payload mapping.
//! - [`webhook`] — Axum router and handler implementations.

// The server module exposes many pub fields that mirror the MS API schema.
// Field-level doc comments are redundant given the module-level table docs,
// so we suppress the missing_docs lint for the entire server tree.
#![allow(missing_docs)]

pub mod auth;
pub mod copilot_studio;
pub mod webhook;
