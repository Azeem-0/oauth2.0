use crate::{
    primitives::UserInfo,
    traits::{OAuthProvider, OAuthProviderFactory},
    types::OAuthClient,
};
use axum::async_trait;
use eyre::{bail, Result};
use reqwest::{Client, Url};
use std::sync::Arc;

/// Twitter OAuth provider implementation
///
/// This struct implements the OAuth provider interface for Twitter.
/// It handles OAuth 2.0 authentication flow and user information
/// retrieval from Twitter's APIs.
///
/// # Fields
///
/// * `client` - HTTP client for making API requests
/// * `oauth_client` - Configured OAuth 2.0 client
/// * `user_info_url` - Twitter's user info endpoint URL
pub struct TwitterProvider {
    /// HTTP client for API requests
    client: Client,
    /// Configured OAuth client
    oauth_client: OAuthClient,
    /// Twitter user info endpoint URL
    user_info_url: Url,
}

impl TwitterProvider {
    /// Creates a new Twitter OAuth provider instance
    ///
    /// This constructor creates a new Twitter provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Twitter
    /// * `user_info_url` - The URL for Twitter's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns a new `TwitterProvider` instance
    pub fn new(oauth_client: OAuthClient, user_info_url: Url) -> Self {
        Self {
            client: Client::new(),
            oauth_client,
            user_info_url,
        }
    }
}

#[async_trait]
impl OAuthProvider for TwitterProvider {
    /// Returns a reference to the OAuth client for Twitter
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient {
        &self.oauth_client
    }

    /// Returns the OAuth scopes required for Twitter
    ///
    /// Twitter requires the "users.read" and "tweet.read" scopes to access
    /// the user's profile information and read tweets.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the required Twitter scopes
    fn get_scopes(&self) -> Vec<String> {
        vec!["users.read".to_string(), "tweet.read".to_string()]
    }

    /// Fetches user information from Twitter's user info endpoint
    ///
    /// This method makes an authenticated request to Twitter's user info
    /// endpoint to retrieve the user's profile information including
    /// their username.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from Twitter
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
            .map_err(|e| eyre::eyre!("Failed to get user info from Twitter: {}", e))?;

        if !response.status().is_success() {
            bail!(
                "Failed to get user info from Twitter: {}",
                response.status()
            );
        }

        let user_data: serde_json::Value = response.json().await?;
        let username = user_data["data"]["username"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("No username field in Twitter user info response"))?
            .to_string();

        Ok(UserInfo {
            id: username,
            provider: "twitter".to_string(),
        })
    }
}

/// Factory for creating Twitter OAuth provider instances
///
/// This struct implements the factory pattern for creating Twitter
/// OAuth provider instances. It allows the application to create
/// provider instances dynamically based on configuration.
pub struct TwitterProviderFactory;

impl OAuthProviderFactory for TwitterProviderFactory {
    /// Creates a new Twitter OAuth provider instance
    ///
    /// This method creates a new Twitter provider with the given
    /// OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for Twitter
    /// * `user_info_url` - The URL for Twitter's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created Twitter provider
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider> {
        Arc::new(TwitterProvider::new(oauth_client, user_info_url))
    }
}
