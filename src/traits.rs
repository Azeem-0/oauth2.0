use async_trait::async_trait;
use eyre::Result;
use reqwest::Url;
use std::sync::Arc;

use crate::{primitives::UserInfo, types::OAuthClient};

/// Core trait for OAuth provider implementations
///
/// This trait defines the interface that all OAuth providers must implement.
/// It provides methods for accessing the OAuth client, getting required scopes,
/// and fetching user information from the provider.
///
/// # Implementors
///
/// All OAuth providers (Google, GitHub, Twitter, Discord, Spotify) implement this trait.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Returns a reference to the OAuth client for this provider
    ///
    /// The OAuth client contains the configured endpoints and credentials
    /// needed to perform OAuth operations with the provider.
    ///
    /// # Returns
    ///
    /// Returns a reference to the configured `OAuthClient` instance
    fn get_oauth_client(&self) -> &OAuthClient;

    /// Returns the OAuth scopes required for this provider
    ///
    /// OAuth scopes define the permissions that the application
    /// requests from the user during the authorization flow.
    ///
    /// # Returns
    ///
    /// Returns a vector of scope strings that will be requested
    /// during the OAuth authorization flow
    fn get_scopes(&self) -> Vec<String>;

    /// Fetches user information from the OAuth provider
    ///
    /// This method makes an authenticated request to the provider's
    /// user info endpoint to retrieve the user's profile information.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The OAuth access token obtained from the provider
    ///
    /// # Returns
    ///
    /// Returns `Result<UserInfo>` containing the user's information
    /// or an error if the request fails
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo>;
}

/// Factory trait for creating OAuth provider instances
///
/// This trait defines the factory pattern for creating OAuth provider
/// instances. Each provider implementation provides a factory that
/// can create instances of that provider.
///
/// # Implementors
///
/// Each OAuth provider has a corresponding factory implementation
/// (GoogleProviderFactory, GithubProviderFactory, etc.)
pub trait OAuthProviderFactory: Send + Sync {
    /// Creates a new OAuth provider instance
    ///
    /// This method creates a new instance of the OAuth provider
    /// with the given OAuth client and user info URL.
    ///
    /// # Arguments
    ///
    /// * `oauth_client` - The configured OAuth client for the provider
    /// * `user_info_url` - The URL for the provider's user info endpoint
    ///
    /// # Returns
    ///
    /// Returns an `Arc<dyn OAuthProvider>` containing the created provider instance
    fn create(&self, oauth_client: OAuthClient, user_info_url: Url) -> Arc<dyn OAuthProvider>;
}
