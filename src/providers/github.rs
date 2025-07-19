use crate::{
    primitives::UserInfo,
    traits::{OAuthProvider, OAuthProviderFactory},
    types::OAuthClient,
};
use axum::async_trait;
use eyre::{bail, Result};
use reqwest::{Client, Url};
use std::sync::Arc;

/// GitHub OAuth provider implementation
///
/// This struct implements the OAuth provider interface for GitHub.
/// It handles OAuth 2.0 authentication flow and user information
/// retrieval from GitHub's APIs.
///
/// # Fields
///
/// * `client` - HTTP client for making API requests
/// * `oauth_client` - Configured OAuth 2.0 client
/// * `user_info_url` - GitHub's user info endpoint URL
pub struct GithubProvider {
    /// HTTP client for API requests
    client: Client,
    /// Configured OAuth client
    oauth_client: OAuthClient,
    /// GitHub user info endpoint URL
    user_info_url: Url,
}

impl GithubProvider {
    /// Creates a new GitHub OAuth provider instance
    ///
    /// This constructor creates a new GitHub provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for GitHub
    /// * `user_info_url` - The URL for GitHub's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns a new `GithubProvider` instance
    pub fn new(oauth_client: OAuthClient, user_info_url: Url) -> Self {
        Self {
            client: Client::new(),
            oauth_client,
            user_info_url,
        }
    }
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    /// Returns a reference to the OAuth client for GitHub
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient {
        &self.oauth_client
    }

    /// Returns the OAuth scopes required for GitHub
    ///
    /// GitHub requires the "user:email" scope to access the user's
    /// email address from their profile information.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the "user:email" scope
    fn get_scopes(&self) -> Vec<String> {
        vec!["user:email".to_string()]
    }

    /// Fetches user information from GitHub's user info endpoint
    ///
    /// This method makes an authenticated request to GitHub's user info
    /// endpoint to retrieve the user's profile information including
    /// their user ID.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from GitHub
    ///
    /// # Returns
    ///
    /// Returns `Result<UserInfo>` containing the user's ID
    /// or an error if the request fails
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo> {
        let request = self
            .client
            .get(self.user_info_url.as_str())
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Garden-Authenticator");

        let response = request
            .send()
            .await
            .map_err(|e| eyre::eyre!("Failed to get user info from Github: {}", e))?;

        if !response.status().is_success() {
            bail!("Failed to get user info from Github: {}", response.status());
        }

        let user_data: serde_json::Value = response.json().await?;

        // GitHub returns user ID as a number, so we need to convert it to string
        let id = user_data["id"]
            .as_u64()
            .ok_or_else(|| eyre::eyre!("No valid user ID in GitHub response"))?
            .to_string();

        Ok(UserInfo {
            id,
            provider: "github".to_string(),
        })
    }
}

/// Factory for creating GitHub OAuth provider instances
///
/// This struct implements the factory pattern for creating GitHub
/// OAuth provider instances. It allows the application to create
/// provider instances dynamically based on configuration.
pub struct GithubProviderFactory;

impl OAuthProviderFactory for GithubProviderFactory {
    /// Creates a new GitHub OAuth provider instance
    ///
    /// This method creates a new GitHub provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for GitHub
    /// * `user_info_url` - The URL for GitHub's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created GitHub provider
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider> {
        Arc::new(GithubProvider::new(oauth_client, user_info_url))
    }
}
