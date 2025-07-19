use axum::{body::Body, http::Response, response::IntoResponse};
use reqwest::StatusCode;

/// Creates an HTTP 500 Internal Server Error response with a custom error message
///
/// This function creates a standardized internal server error response that
/// can be returned from request handlers when an unexpected error occurs.
///
/// # Arguments
///
/// * `message` - The error message to include in the response body
///
/// Returns an HTTP response with:
/// - Status code: 500 Internal Server Error
/// - Body: The provided error message as a string
pub fn internal_error(message: &str) -> Response<Body> {
    (StatusCode::INTERNAL_SERVER_ERROR, message.to_string()).into_response()
}

/// Creates an HTTP 400 Bad Request response with a custom error message
///
/// This function creates a standardized bad request response that can be
/// returned from request handlers when the client provides invalid data
/// or makes an invalid request.
///
/// # Arguments
///
/// * `message` - The error message to include in the response body
///
/// Returns an HTTP response with:
/// - Status code: 400 Bad Request
/// - Body: The provided error message as a string
pub fn bad_request(message: &str) -> Response<Body> {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}
