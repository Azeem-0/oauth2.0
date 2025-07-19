use crate::{
    primitives::UserInfo,
    traits::{OAuthProvider, OAuthProviderFactory},
    types::OAuthClient,
};
use axum::async_trait;
use eyre::{bail, Result};
use reqwest::{Client, Url};
use std::sync::Arc;

/// Discord OAuth provider implementation
///
/// This struct implements the OAuth provider interface for Discord.
/// It handles OAuth 2.0 authentication flow and user information
/// retrieval from Discord's APIs.
///
/// # Fields
///
/// * `client` - HTTP client for making API requests
/// * `oauth_client` - Configured OAuth 2.0 client
/// * `user_info_url` - Discord's user info endpoint URL
pub struct DiscordProvider {
    /// HTTP client for API requests
    client: Client,
    /// Configured OAuth client
    oauth_client: OAuthClient,
    /// Discord user info endpoint URL
    user_info_url: Url,
}

impl DiscordProvider {
    /// Creates a new Discord OAuth provider instance
    ///
    /// This constructor creates a new Discord provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Discord
    /// * `user_info_url` - The URL for Discord's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns a new `DiscordProvider` instance
    pub fn new(oauth_client: OAuthClient, user_info_url: Url) -> Self {
        Self {
            client: Client::new(),
            oauth_client,
            user_info_url,
        }
    }
}

#[async_trait]
impl OAuthProvider for DiscordProvider {
    /// Returns a reference to the OAuth client for Discord
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient {
        &self.oauth_client
    }

    /// Returns the OAuth scopes required for Discord
    ///
    /// Discord requires the "identify" scope to access the user's
    /// basic profile information including their username.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the "identify" scope
    fn get_scopes(&self) -> Vec<String> {
        vec!["identify".to_string()]
    }

    /// Fetches user information from Discord's user info endpoint
    ///
    /// This method makes an authenticated request to Discord's user info
    /// endpoint to retrieve the user's profile information including
    /// their username.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from Discord
    ///
    /// # Returns
    ///
    /// Returns `Result<UserInfo>` containing the user's username
    /// or an error if the request fails
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo> {
        let request = self
            .client
            .get(self.user_info_url.as_str())
            .header("Authorization", format!("Bearer {}", access_token));

        let response = request
            .send()
            .await
            .map_err(|e| eyre::eyre!("Failed to get user info from Discord: {}", e))?;

        if !response.status().is_success() {
            bail!(
                "Failed to get user info from Discord: {}",
                response.status()
            );
        }

        let user_data: serde_json::Value = response.json().await?;
        let username = user_data["username"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("No username field in Discord user info response"))?
            .to_string();

        Ok(UserInfo {
            id: username,
            provider: "discord".to_string(),
        })
    }
}

/// Factory for creating Discord OAuth provider instances
///
/// This struct implements the factory pattern for creating Discord
/// OAuth provider instances. It allows the application to create
/// provider instances dynamically based on configuration.
pub struct DiscordProviderFactory;

impl OAuthProviderFactory for DiscordProviderFactory {
    /// Creates a new Discord OAuth provider instance
    ///
    /// This method creates a new Discord provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Discord
    /// * `user_info_url` - The URL for Discord's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created Discord provider
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider> {
        Arc::new(DiscordProvider::new(oauth_client, user_info_url))
    }
}
