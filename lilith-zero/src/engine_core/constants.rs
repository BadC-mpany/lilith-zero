// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

pub mod jsonrpc {
    pub const ERROR_SECURITY_BLOCK: i32 = -32000;
    pub const ERROR_AUTH: i32 = -32001;
    pub const ERROR_METHOD_NOT_FOUND: i32 = -32601;
    pub const ERROR_INVALID_REQUEST: i32 = -32600;
    pub const ERROR_INTERNAL: i32 = -32603;
    pub const ERROR_PARSE: i32 = -32700;
}

pub mod crypto {
    pub const SECRET_KEY_LENGTH: usize = 32;
    pub const SESSION_ID_VERSION: &str = "1";
}

pub mod spotlight {
    pub const DATA_START_PREFIX: &str = "<<<LILITH_ZERO_DATA_START:";
    pub const DATA_END_PREFIX: &str = "<<<LILITH_ZERO_DATA_END:";
    pub const DELIMITER_SUFFIX: &str = ">>>";
    pub const RANDOM_ID_LENGTH: usize = 8;
}

pub mod policy {
    pub const ACTION_ALLOW: &str = "ALLOW";
    pub const ACTION_DENY: &str = "DENY";
    pub const DEFAULT_POLICY_ID: &str = "default";
    pub const DEFAULT_POLICY_NAME: &str = "Permissive Default";
}

pub mod session {
    pub const SESSION_ID_ENV_PREFIX: &str = "LILITH_ZERO_SESSION_ID=";
    pub const SESSION_ID_PARAM: &str = "_lilith_zero_session_id";
}

pub mod config {
    pub const ENV_POLICIES_YAML_PATH: &str = "POLICIES_YAML_PATH";
    pub const ENV_LOG_LEVEL: &str = "LOG_LEVEL";
    pub const ENV_LOG_FORMAT: &str = "LOG_FORMAT";
    pub const ENV_OWNER: &str = "LILITH_ZERO_OWNER";
    pub const ENV_EXPECTED_AUDIENCE: &str = "LILITH_ZERO_EXPECTED_AUDIENCE";
    pub const ENV_SECURITY_LEVEL: &str = "LILITH_ZERO_SECURITY_LEVEL";
    pub const ENV_MCP_VERSION: &str = "LILITH_ZERO_MCP_VERSION";
}

pub mod methods {
    pub const INITIALIZE: &str = "initialize";
    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";
}

pub mod limits {
    pub const MAX_MESSAGE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
}
