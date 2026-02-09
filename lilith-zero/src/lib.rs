// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
