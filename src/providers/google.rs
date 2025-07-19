use crate::{
    primitives::UserInfo,
    traits::{OAuthProvider, OAuthProviderFactory},
    types::OAuthClient,
};
use axum::async_trait;
use eyre::{bail, Result};
use reqwest::{Client, Url};
use std::sync::Arc;

/// Google OAuth provider implementation
///
/// This struct implements the OAuth provider interface for Google.
/// It handles OAuth 2.0 authentication flow and user information
/// retrieval from Google's APIs.
///
/// # Fields
///
/// * `client` - HTTP client for making API requests
/// * `oauth_client` - Configured OAuth 2.0 client
/// * `user_info_url` - Google's user info endpoint URL
pub struct GoogleProvider {
    /// HTTP client for API requests
    client: Client,
    /// Configured OAuth client
    oauth_client: OAuthClient,
    /// Google user info endpoint URL
    user_info_url: Url,
}

impl GoogleProvider {
    /// Creates a new Google OAuth provider instance
    ///
    /// This constructor creates a new Google provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Google
    /// * `user_info_url` - The URL for Google's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns a new `GoogleProvider` instance
    pub fn new(oauth_client: OAuthClient, user_info_url: Url) -> Self {
        Self {
            client: Client::new(),
            oauth_client,
            user_info_url,
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    /// Returns a reference to the OAuth client for Google
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient {
        &self.oauth_client
    }

    /// Returns the OAuth scopes required for Google
    ///
    /// Google requires the "email" scope to access the user's email address
    /// from their profile information.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the "email" scope
    fn get_scopes(&self) -> Vec<String> {
        vec!["email".to_string()]
    }

    /// Fetches user information from Google's user info endpoint
    ///
    /// This method makes an authenticated request to Google's user info
    /// endpoint to retrieve the user's profile information including
    /// their email address.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from Google
    ///
    /// # Returns
    ///
    /// Returns `Result<UserInfo>` containing the user's email address
    /// or an error if the request fails
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo> {
        let request = self
            .client
            .get(self.user_info_url.as_str())
            .header("Authorization", format!("Bearer {}", access_token));

        let response = request
            .send()
            .await
            .map_err(|e| eyre::eyre!("Failed to get user info from Google: {}", e))?;

        if !response.status().is_success() {
            bail!("Failed to get user info from Google: {}", response.status());
        }

        let user_data: serde_json::Value = response.json().await?;

        let email = user_data
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre::eyre!("No email field in Google user info response"))?
            .to_string();

        Ok(UserInfo {
            id: email,
            provider: "google".to_string(),
        })
    }
}

/// Factory for creating Google OAuth provider instances
///
/// This struct implements the factory pattern for creating Google
/// OAuth provider instances. It allows the application to create
/// provider instances dynamically based on configuration.
pub struct GoogleProviderFactory;

impl OAuthProviderFactory for GoogleProviderFactory {
    /// Creates a new Google OAuth provider instance
    ///
    /// This method creates a new Google provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Google
    /// * `user_info_url` - The URL for Google's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created Google provider
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider> {
        Arc::new(GoogleProvider::new(oauth_client, user_info_url))
    }
}
