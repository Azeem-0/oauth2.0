//! OAuth 2.0 Server
//!
//! This module provides the main entry point for the OAuth 2.0 server application.
//! It initializes the server with configured OAuth providers and starts the HTTP server.

use crate::{
    providers::OAUTH_PROVIDER_REGISTRY,
    server::server::{AppState, Server},
    settings::OAuthSettings,
    traits::OAuthProvider,
};
use eyre::Result;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Url;
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn};

mod primitives;
mod providers;
mod server;
mod settings;
mod traits;
mod types;

/// Main application entry point
///
/// Initializes the OAuth 2.0 server with the following steps:
/// 1. Sets up tracing for logging
/// 2. Loads configuration from Settings.toml
/// 3. Builds OAuth providers from configuration
/// 4. Creates application state with providers
/// 5. Starts the HTTP server
///
/// # Returns
///
/// Returns `Result<(), Box<dyn std::error::Error>>` indicating success or failure
///
/// # Errors
///
/// - Configuration loading errors
/// - OAuth provider initialization errors
/// - Server startup errors
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let settings = settings::Settings::from_toml("Settings.toml");

    let oauth_providers = build_oauth_providers(&settings.oauth).unwrap();

    let app_state = Arc::new(AppState { oauth_providers });

    info!("Starting server on port {}", settings.port);

    let app = Server::new(settings.port, app_state);

    app.run().await;

    Ok(())
}

/// Builds OAuth provider instances from configuration
///
/// This function creates OAuth client instances for each provider configured
/// in the settings. It validates URLs, creates OAuth clients, and registers
/// them with the provider factory.
///
/// # Arguments
///
/// * `oauth` - HashMap containing OAuth provider configurations
///
/// # Returns
///
/// Returns `Result<HashMap<String, Arc<dyn OAuthProvider>>>` containing
/// the initialized OAuth providers mapped by provider name
fn build_oauth_providers(
    oauth: &HashMap<String, OAuthSettings>,
) -> Result<HashMap<String, Arc<dyn OAuthProvider>>> {
    let mut oauth_providers = HashMap::new();

    for (provider_name, provider_config) in oauth.iter() {
        // Validate the required urls
        let auth_url = AuthUrl::new(provider_config.auth_url.to_string())
            .expect(&format!("Invalid auth_url for provider {}", provider_name));

        let token_url = TokenUrl::new(provider_config.token_url.to_string())
            .expect(&format!("Invalid token_url for provider {}", provider_name));

        let redirect_url = RedirectUrl::new(provider_config.redirect_uri.to_string()).expect(
            &format!("Invalid redirect_uri for provider {}", provider_name),
        );

        let user_info_url = Url::parse(&provider_config.user_info_url).expect(&format!(
            "Invalid user_info_url for provider {}",
            provider_name
        ));

        // Create the OAuth client
        let client = BasicClient::new(ClientId::new(provider_config.client_id.clone()))
            .set_client_secret(ClientSecret::new(provider_config.client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        // Get the OAuth provider factory
        if let Some(factory) = OAUTH_PROVIDER_REGISTRY.get(provider_name.as_str()) {
            // Create the OAuth provider instance
            let provider = factory.create(client, user_info_url);
            oauth_providers.insert(provider_name.clone(), provider);
        } else {
            warn!(
                "OAuth provider {} not configured in the factory",
                provider_name
            );
        }
    }

    Ok(oauth_providers)
}
