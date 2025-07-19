use config::{Config, File};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main application settings structure
///
/// Contains all configuration settings for the OAuth 2.0 server including
/// the server port and OAuth provider configurations.
///
/// # Fields
///
/// * `port` - The port number the server will listen on
/// * `oauth` - HashMap of OAuth provider configurations keyed by provider name
#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    /// Server port number
    pub port: u16,
    /// OAuth provider configurations
    pub oauth: HashMap<String, OAuthSettings>,
}

impl Settings {
    /// Loads settings from a TOML configuration file
    ///
    /// This function reads the specified TOML file and deserializes it into
    /// a Settings structure. The file should contain server configuration
    /// and OAuth provider settings.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    ///
    /// Returns a `Settings` instance with the loaded configuration
    pub fn from_toml(path: &str) -> Self {
        let config = Config::builder()
            .add_source(File::with_name(path))
            .build()
            .unwrap();
        config
            .try_deserialize()
            .expect("Failed to deserialize settings")
    }
}

/// OAuth provider configuration structure
///
/// Contains all the necessary configuration for a single OAuth provider
/// including client credentials and endpoint URLs.
///
/// # Fields
///
/// * `client_id` - OAuth client ID from the provider
/// * `client_secret` - OAuth client secret from the provider
/// * `auth_url` - OAuth authorization endpoint URL
/// * `token_url` - OAuth token exchange endpoint URL
/// * `redirect_uri` - OAuth redirect URI (must match provider configuration)
/// * `user_info_url` - Provider's user info endpoint URL
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthSettings {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    pub client_secret: String,
    /// OAuth authorization URL
    pub auth_url: String,
    /// OAuth token URL
    pub token_url: String,
    /// OAuth redirect URI
    pub redirect_uri: String,
    /// User info endpoint URL
    pub user_info_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that settings can be deserialized from TOML
    ///
    /// This test ensures that the Settings structure can be properly
    /// loaded from a TOML configuration file and that at least one
    /// OAuth provider is configured.
    #[test]
    fn test_deserialize_settings() {
        let path = "Settings.toml";
        let settings = Settings::from_toml(path);
        assert!(settings.oauth.len() > 0);
    }
}
