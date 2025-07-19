use crate::{
    primitives::OAuthSessionState,
    server::{
        errors::{bad_request, internal_error},
        server::AppState,
    },
};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_sessions::Session;

/// Session key for storing OAuth session state
const OAUTH_SESSION_STATE_KEY: &str = "oauth_session_state";

/// Query parameters for OAuth authorization initiation
///
/// This struct represents the query parameters expected when initiating
/// an OAuth flow. It contains the provider name to use for authentication.
///
/// # Fields
///
/// * `provider` - The name of the OAuth provider (e.g., "google", "github")
#[derive(Debug, Deserialize)]
pub struct InitiateQueryParams {
    /// OAuth provider name
    provider: String,
}

/// Health check endpoint handler
///
/// This handler provides a simple health check endpoint that can be used
/// by load balancers or monitoring systems to verify the server is running.
///
/// # Returns
///
/// Returns a static string "OK" indicating the server is healthy
pub async fn health_check() -> &'static str {
    "OK"
}

/// OAuth authorization initiation handler
///
/// This handler initiates the OAuth 2.0 flow by:
/// 1. Validating the requested provider
/// 2. Generating PKCE challenge and verifier for security
/// 3. Creating CSRF token for protection
/// 4. Storing session state
/// 5. Redirecting to the OAuth provider's authorization URL
///
/// # Arguments
///
/// * `state` - Shared application state containing OAuth providers
/// * `params` - Query parameters containing the provider name
/// * `session` - Session for storing OAuth state
///
/// # Returns
///
/// Returns a redirect response to the OAuth provider's authorization URL
/// or an error response if the provider is invalid or session storage fails
pub async fn oauth_authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<InitiateQueryParams>,
    session: Session,
) -> impl IntoResponse {
    let oauth_provider = match state.oauth_providers.get(&params.provider) {
        Some(provider) => provider,
        None => {
            tracing::warn!("Invalid OAuth provider requested: {}", params.provider);
            return bad_request("Invalid provider");
        }
    };

    // Generate PKCE challenge
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let scopes = oauth_provider.get_scopes();
    // Generate CSRF token
    let (auth_url, csrf_token) = oauth_provider
        .get_oauth_client()
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes.iter().map(|s| Scope::new(s.to_string())))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    // Create the session state
    let oauth_session_state = OAuthSessionState::new(
        params.provider.clone(),
        pkce_code_verifier.secret().to_string(),
        csrf_token.secret().to_string(),
    );

    // Store the state in the session
    if let Err(e) = session
        .insert(OAUTH_SESSION_STATE_KEY, oauth_session_state)
        .await
    {
        tracing::warn!("Failed to insert OAuth state into session: {}", e);
        return internal_error("Failed to insert OAuth state into session");
    }

    Redirect::to(auth_url.as_str()).into_response()
}

/// Query parameters for OAuth callback processing
///
/// This struct represents the query parameters expected when the OAuth
/// provider redirects back to the callback endpoint.
///
/// # Fields
///
/// * `code` - The authorization code returned by the OAuth provider
/// * `state` - The CSRF state token for validation
#[derive(Debug, Deserialize)]
pub struct CallbackQueryParams {
    /// OAuth authorization code
    code: String,
    /// CSRF state token
    state: String,
}

/// Response structure for OAuth callback
///
/// This struct represents the response returned after successful OAuth
/// authentication. It contains the user's unique identifier.
///
/// # Fields
///
/// * `user_id` - The user's unique identifier (email, user ID, etc.)
#[derive(Debug, Deserialize, Serialize)]
pub struct CallbackResponse {
    /// User's unique identifier
    pub user_id: String,
}

impl IntoResponse for CallbackResponse {
    /// Converts the callback response to an HTTP response
    ///
    /// # Returns
    ///
    /// Returns a JSON response containing the user ID
    fn into_response(self) -> axum::response::Response {
        axum::Json(self).into_response()
    }
}

/// OAuth callback handler
///
/// This handler processes the OAuth callback from the provider by:
/// 1. Retrieving and validating session state
/// 2. Validating CSRF token
/// 3. Exchanging authorization code for access token
/// 4. Fetching user information from the provider
/// 5. Returning user information in JSON format
///
/// # Arguments
///
/// * `state` - Shared application state containing OAuth providers
/// * `params` - Query parameters containing authorization code and state
/// * `session` - Session for retrieving OAuth state
///
/// # Returns
///
/// Returns a JSON response with the user's unique identifier
/// or an error response if any step fails
pub async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackQueryParams>,
    session: Session,
) -> impl IntoResponse {
    // Retrieve the state from the session
    let oauth_session_state: OAuthSessionState = {
        let result = match session.get(OAUTH_SESSION_STATE_KEY).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("Failed to retrieve OAuth session state from session: {}", e);
                return internal_error("Failed to retrieve OAuth session state from session");
            }
        };

        match result {
            Some(state) => state,
            None => {
                tracing::warn!("OAuth session state not found in session");
                return bad_request("OAuth session state not found in session");
            }
        }
    };

    // Compare csrf token
    if oauth_session_state.csrf_token != params.state {
        tracing::warn!("CSRF token mismatch");
        return bad_request("CSRF token mismatch");
    }

    // Retrieve the provider from the state
    let oauth_provider = match state.oauth_providers.get(&oauth_session_state.provider) {
        Some(provider) => provider,
        None => {
            tracing::warn!(
                "Invalid OAuth provider in callback: {}",
                oauth_session_state.provider
            );
            return bad_request("Invalid provider");
        }
    };

    let http_client = match reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!("Failed to build HTTP client: {}", e);
            return internal_error("Failed to build HTTP client");
        }
    };

    // Exchange authorization code for token
    let token = match oauth_provider
        .get_oauth_client()
        .exchange_code(AuthorizationCode::new(params.code.clone()))
        .set_pkce_verifier(PkceCodeVerifier::new(
            oauth_session_state.pkce_verifier.clone(),
        ))
        .request_async(&http_client)
        .await
    {
        Ok(token) => token,
        Err(e) => {
            tracing::warn!(
                "OAuth token exchange failed for provider {}: {}",
                oauth_session_state.provider,
                e
            );
            return bad_request("OAuth token exchange failed");
        }
    };

    let access_token = token.access_token().secret().to_string();

    // Get user info from provider
    let user_info = match oauth_provider.get_user_info(&access_token).await {
        Ok(user_info) => user_info,
        Err(e) => {
            tracing::warn!(
                "Failed to get user info from provider {}: {}",
                oauth_session_state.provider,
                e
            );
            return internal_error("Failed to get user info");
        }
    };

    CallbackResponse {
        user_id: user_info.id,
    }
    .into_response()
}

/// Home page handler for OAuth testing
///
/// This handler provides a simple HTML page with buttons for testing
/// OAuth flows with different providers. It includes styled buttons
/// for Google, GitHub, Twitter, and Discord authentication.
///
/// # Returns
///
/// Returns an HTML page with OAuth provider buttons for testing
/// the OAuth flow with different providers
pub async fn home_page() -> impl IntoResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Test Page</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        h1 {
            color: #333;
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
        }
        .oauth-buttons {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-top: 1.5rem;
        }
        .oauth-button {
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
            border: none;
            color: white;
        }
        .oauth-button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        .oauth-button:active {
            transform: translateY(0);
        }
        .google-button {
            background: #4285f4;
        }
        .google-button:hover {
            background: #3367d6;
        }
        .github-button {
            background: #24292e;
        }
        .github-button:hover {
            background: #1a1e22;
        }
        .twitter-button {
            background: #1da1f2;
        }
        .twitter-button:hover {
            background: #1a8cd8;
        }
        .discord-button {
            background: #5865f2;
        }
        .discord-button:hover {
            background: #4752c4;
        }
        .spotify-button {
            background: #1ed760;
        }
        .spotify-button:hover {
            background: #16b34a;
        }
        .status {
            margin-top: 1rem;
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 14px;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 OAuth Test</h1>
        <p>Test your OAuth 2.0 implementation</p>
        
        <div class="oauth-buttons">
            <a href="/oauth/authorize?provider=google" class="oauth-button google-button">
                <svg width="18" height="18" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Sign in with Google
            </a>
            
            <a href="/oauth/authorize?provider=github" class="oauth-button github-button">
                <svg width="18" height="18" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
                Sign in with GitHub
            </a>

            <a href="/oauth/authorize?provider=twitter" class="oauth-button twitter-button">
                <svg width="18" height="18" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M24 4.557a9.83 9.83 0 0 1-2.828.775 4.932 4.932 0 0 0 2.168-2.728 9.864 9.864 0 0 1-3.127 1.195 4.916 4.916 0 0 0-8.394 4.49 13.925 13.925 0 0 1-10.025-5.028 4.902 4.902 0 0 0 1.523 6.574 4.906 4.906 0 0 1-2.23-1.227v.05c0 4.741 3.337 8.73 7.928 9.75a10.007 10.007 0 0 1-8.451 2.296 13.934 13.934 0 0 0 7.546 2.212c9.142 0 14.307-7.721 13.995-14.646A10.025 10.025 0 0 0 24 4.557z"/>
                </svg>
                Sign in with Twitter    
            </a>

            <a href="/oauth/authorize?provider=discord" class="oauth-button discord-button">
                <svg width="18" height="18" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419-.019 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1568 2.4189Z"/>
                </svg>
                Sign in with Discord
            </a>

            <a href="/oauth/authorize?provider=spotify" class="oauth-button spotify-button">
                <svg width="18" height="18" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/>
                </svg>
                Sign in with Spotify
            </a>
        </div>
        
        <div id="status"></div>
    </div>

    <script>
        // Check if we have a token in the URL (from callback)
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        
        if (token) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status success';
            statusDiv.innerHTML = `
                <strong>✅ Authentication Successful!</strong><br>
                <small>JWT Token: ${token.substring(0, 50)}...</small>
            `;
        }
        
        // Check for error parameters
        const error = urlParams.get('error');
        if (error) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = 'status error';
            statusDiv.innerHTML = `<strong>❌ Error:</strong> ${error}`;
        }
    </script>
</body>
</html>
    "#;

    Html(html)
}
