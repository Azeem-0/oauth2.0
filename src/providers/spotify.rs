use crate::{
    primitives::UserInfo,
    traits::{OAuthProvider, OAuthProviderFactory},
    types::OAuthClient,
};
use axum::async_trait;
use eyre::Result;
use reqwest::{Client, Url};
use std::sync::Arc;

/// Spotify OAuth provider implementation
///
/// This struct implements the OAuth provider interface for Spotify.
/// It handles OAuth 2.0 authentication flow and user information
/// retrieval from Spotify's APIs.
///
/// # Fields
///
/// * `oauth_client` - Configured OAuth 2.0 client
/// * `client` - HTTP client for making API requests
/// * `user_info_url` - Spotify's user info endpoint URL
pub struct SpotifyProvider {
    /// Configured OAuth client
    oauth_client: OAuthClient,
    /// HTTP client for API requests
    client: Client,
    /// Spotify user info endpoint URL
    user_info_url: Url,
}

impl SpotifyProvider {
    /// Creates a new Spotify OAuth provider instance
    ///
    /// This constructor creates a new Spotify provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Spotify
    /// * `user_info_url` - The URL for Spotify's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns a new `SpotifyProvider` instance
    pub fn new(oauth_client: OAuthClient, user_info_url: Url) -> Self {
        Self {
            oauth_client,
            client: Client::new(),
            user_info_url,
        }
    }
}

#[async_trait]
impl OAuthProvider for SpotifyProvider {
    /// Returns a reference to the OAuth client for Spotify
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient {
        &self.oauth_client
    }

    /// Returns the OAuth scopes required for Spotify
    ///
    /// Spotify requires the "user-read-email" scope to access the user's
    /// email address from their profile information.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the "user-read-email" scope
    fn get_scopes(&self) -> Vec<String> {
        vec!["user-read-email".to_string()]
    }

    /// Fetches user information from Spotify's user info endpoint
    ///
    /// This method makes an authenticated request to Spotify's user info
    /// endpoint to retrieve the user's profile information including
    /// their user ID.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from Spotify
    ///
    /// # Returns
    ///
    /// Returns `Result<UserInfo>` containing the user's ID
    /// or an error if the request fails
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo> {
        let request = self
            .client
            .get(self.user_info_url.as_str())
            .header("Authorization", format!("Bearer {}", access_token));

        let response = request
            .send()
            .await
            .map_err(|e| eyre::eyre!("Failed to get user info from Spotify: {}", e))?;

        if !response.status().is_success() {
            return Err(eyre::eyre!(
                "Failed to get user info from Spotify: {}",
                response.status()
            ));
        }

        let user_data: serde_json::Value = response.json().await?;
        let id = user_data
            .get("id")
            .ok_or_else(|| eyre::eyre!("No id field in Spotify user info response"))?
            .to_string();

        Ok(UserInfo {
            id,
            provider: "spotify".to_string(),
        })
    }
}

/// Factory for creating Spotify OAuth provider instances
///
/// This struct implements the factory pattern for creating Spotify
/// OAuth provider instances. It allows the application to create
/// provider instances dynamically based on configuration.
pub struct SpotifyProviderFactory;

impl OAuthProviderFactory for SpotifyProviderFactory {
    /// Creates a new Spotify OAuth provider instance
    ///
    /// This method creates a new Spotify provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Spotify
    /// * `user_info_url` - The URL for Spotify's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created Spotify provider
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider> {
        Arc::new(SpotifyProvider::new(oauth_client, user_info_url))
    }
}
