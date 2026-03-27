// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and


use crate::engine_core::taint::Tainted;
use crate::engine_core::types::TaintedString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SecurityEvent {
    Handshake {
        protocol_version: String,
        client_info: Value,
        audience_token: Option<String>,
        capabilities: Value,
    },
    ToolRequest {
        request_id: Value,
        tool_name: TaintedString,
        arguments: Tainted<Value>,
        session_token: Option<String>,
    },
    ResourceRequest {
        request_id: Value,
        uri: TaintedString,
        session_token: Option<String>,
    },
    Passthrough {
        request_id: Option<Value>,
        method: String,
        params: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecurityDecision {
    Allow,
    AllowWithTransforms {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
        output_transforms: Vec<OutputTransform>,
    },
    Deny {
        error_code: i32,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OutputTransform {
    Spotlight {
        json_paths: Vec<String>,
    },
    Redact { json_paths: Vec<String> },
}
