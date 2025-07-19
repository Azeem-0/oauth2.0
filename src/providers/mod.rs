use crate::{
    providers::{
        discord::DiscordProviderFactory, github::GithubProviderFactory,
        google::GoogleProviderFactory, spotify::SpotifyProviderFactory,
        twitter::TwitterProviderFactory,
    },
    traits::OAuthProviderFactory,
};
use once_cell::sync::Lazy;
use std::{collections::HashMap, sync::Arc};

mod discord;
mod github;
mod google;
mod spotify;
mod twitter;

/// Global registry of OAuth provider factories
///
/// This static registry contains all available OAuth provider factories
/// mapped by their provider names. It allows the application to dynamically
/// create provider instances based on configuration.
///
/// # Supported Providers
///
/// - `"google"` - Google OAuth provider
/// - `"github"` - GitHub OAuth provider
/// - `"twitter"` - Twitter OAuth provider
/// - `"discord"` - Discord OAuth provider
/// - `"spotify"` - Spotify OAuth provider
///
/// # Usage
///
/// The registry is used in the main application to create provider instances
/// based on the configuration in Settings.toml.
pub static OAUTH_PROVIDER_REGISTRY: Lazy<
    HashMap<&'static str, Arc<dyn OAuthProviderFactory + Send + Sync>>,
> = Lazy::new(|| {
    let mut m: HashMap<&'static str, Arc<dyn OAuthProviderFactory + Send + Sync>> = HashMap::new();
    // Register Google OAuth provider
    m.insert("google", Arc::new(GoogleProviderFactory));

    // Register Github OAuth provider
    m.insert("github", Arc::new(GithubProviderFactory));

    // Register Twitter OAuth provider
    m.insert("twitter", Arc::new(TwitterProviderFactory));

    // Register Discord OAuth provider
    m.insert("discord", Arc::new(DiscordProviderFactory));

    // Register Spotify OAuth provider
    m.insert("spotify", Arc::new(SpotifyProviderFactory));

    m
});
