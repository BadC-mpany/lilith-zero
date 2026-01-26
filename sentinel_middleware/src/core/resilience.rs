use failsafe::{backoff, failure_policy, Config, StateMachine, Error};
use failsafe::futures::CircuitBreaker; // Import Async CircuitBreaker trait
use std::time::Duration;
use crate::core::errors::InterceptorError;

/// Standard Circuit Breaker Type for Sentinel
/// 
/// Policy:
/// - 5 consecutive failures triggers OPEN state
/// - 5 seconds cool-down period before HALF-OPEN (retry)
pub type SentinelCircuitBreaker = StateMachine<
    failure_policy::ConsecutiveFailures<backoff::Constant>,
    ()
>;

/// Create a new standard circuit breaker instance
pub fn create_circuit_breaker() -> SentinelCircuitBreaker {
    Config::new()
        .failure_policy(failure_policy::consecutive_failures(
            5,
            backoff::constant(Duration::from_secs(5)),
        ))
        .build()
}

/// Execute a fallible async operation within the circuit breaker protection
/// 
/// Automatically handles:
/// - Circuit state checks (Closed/Open/Half-Open)
/// - Failure counting
/// - Error mapping to InterceptorError::TransientError if Open
pub async fn execute_with_cb<F, Fut, T, E>(
    cb: &SentinelCircuitBreaker,
    operation: F
) -> Result<T, InterceptorError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    // Ensure error can be converted/displayed and tracked by failsafe
    E: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static, 
{
    // Check if call is permitted via the circuit breaker
    // cb.call(future) returns ResponseFuture which we must await.
    // The await returns Result<T, Error<E>>.
    match cb.call(operation()).await {
        Ok(val) => Ok(val),
        Err(Error::Inner(e)) => {
            // Inner error - operation failed (circuit might count this failure)
            Err(InterceptorError::DependencyFailure { 
                service: "CircuitBreakerWrappedService".to_string(), 
                error: e.to_string() 
            })
        },
        Err(Error::Rejected) => {
             Err(InterceptorError::TransientError(
                "Circuit Breaker Open: Service Unavailable".to_string()
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let cb = create_circuit_breaker();

        // Fail 5 times
        for _ in 0..5 {
            let result = execute_with_cb(&cb, || async {
                Err::<(), _>(io::Error::new(io::ErrorKind::Other, "failure"))
            }).await;
            
            match result {
                Err(InterceptorError::DependencyFailure { .. }) => {}, // Expected
                _ => panic!("Expected DependencyFailure, got {:?}", result),
            }
        }

        // 6th time should be rejected (Circuit Open)
        // Even if the operation would succeed, the CB prevents it
        let result = execute_with_cb(&cb, || async {
            Ok::<(), io::Error>(()) 
        }).await;

        match result {
            Err(InterceptorError::TransientError(msg)) => {
                assert!(msg.contains("Circuit Breaker Open"));
            }
            _ => panic!("Expected Circuit Breaker Open error, got {:?}", result),
        }
    }
}
