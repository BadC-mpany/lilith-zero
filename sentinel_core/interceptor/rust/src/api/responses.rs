// Response types for API endpoints

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Success response for proxy execute endpoint
#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub result: serde_json::Value,
}

/// Error response structure
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub redis: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

/// API error type that converts domain errors to HTTP responses
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub request_id: Option<String>,
}

impl ApiError {
    /// Create a new API error
    pub fn new(status: StatusCode, message: String) -> Self {
        Self {
            status,
            message,
            request_id: None,
        }
    }

    /// Create a new API error with request ID
    pub fn with_request_id(status: StatusCode, message: String, request_id: String) -> Self {
        Self {
            status,
            message,
            request_id: Some(request_id),
        }
    }

    /// Create from InterceptorError
    pub fn from_interceptor_error(err: crate::core::errors::InterceptorError) -> Self {
        let status = StatusCode::from_u16(err.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let message = err.user_message();
        Self {
            status,
            message,
            request_id: None,
        }
    }

    /// Create from InterceptorError with request ID
    pub fn from_interceptor_error_with_id(
        err: crate::core::errors::InterceptorError,
        request_id: String,
    ) -> Self {
        let status = StatusCode::from_u16(err.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let message = err.user_message();
        Self {
            status,
            message,
            request_id: Some(request_id),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.message,
            request_id: self.request_id,
        });
        (self.status, body).into_response()
    }
}

impl From<crate::core::errors::InterceptorError> for ApiError {
    fn from(err: crate::core::errors::InterceptorError) -> Self {
        ApiError::from_interceptor_error(err)
    }
}
