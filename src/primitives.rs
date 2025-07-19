use serde::{Deserialize, Serialize};

/// OAuth session state for tracking OAuth flow
///
/// This structure holds the state information needed to complete an OAuth flow.
/// It includes the provider name, PKCE verifier for security, and CSRF token
/// for protection against cross-site request forgery attacks.
///
/// # Fields
///
/// * `provider` - The name of the OAuth provider (e.g., "google", "github")
/// * `pkce_verifier` - The PKCE code verifier used for enhanced security
/// * `csrf_token` - The CSRF token for protecting against CSRF attacks
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthSessionState {
    /// OAuth provider name (google, github, etc.)
    pub provider: String,
    /// PKCE code verifier for security
    pub pkce_verifier: String,
    /// CSRF state token for security
    pub csrf_token: String,
}

impl OAuthSessionState {
    /// Creates a new OAuth session state instance
    ///
    /// This constructor creates a new session state with the provided
    /// provider name, PKCE verifier, and CSRF token.
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OAuth provider
    /// * `pkce_verifier` - The PKCE code verifier string
    /// * `csrf_token` - The CSRF token string
    ///
    /// # Returns
    ///
    /// Returns a new `OAuthSessionState` instance
    pub fn new(provider: String, pkce_verifier: String, csrf_token: String) -> Self {
        Self {
            provider,
            pkce_verifier,
            csrf_token,
        }
    }
}

/// User information returned from OAuth providers
///
/// This structure contains the basic user information that is returned
/// from OAuth providers after successful authentication. The structure
/// is designed to be generic enough to work with multiple providers.
///
/// # Fields
///
/// * `id` - The user's unique identifier (usually email or user ID)
/// * `provider` - The name of the OAuth provider that provided this information
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    /// User's unique identifier (email, user ID, etc.)
    pub id: String,
    /// OAuth provider name
    pub provider: String,
}
