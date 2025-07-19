use crate::{
    server::handlers::{health_check, home_page, oauth_authorize, oauth_callback},
    traits::OAuthProvider,
};
use axum::{
    extract::{MatchedPath, Request},
    http::Method,
    routing::get,
    Router,
};
use std::{collections::HashMap, sync::Arc};
use tower_http::{
    cors::{AllowHeaders, Any, CorsLayer},
    trace::TraceLayer,
};
use tower_sessions::{cookie::time::Duration, Expiry, SessionManagerLayer};
use tower_sessions_moka_store::MokaStore;
use tracing::info_span;

/// Cache TTL for session data (1 hour)
const CACHE_TTL: Duration = Duration::seconds(3600);

/// Application state shared across request handlers
///
/// This struct holds the shared state that is accessible to all
/// request handlers. It contains the OAuth providers configured
/// for the application.
///
/// # Fields
///
/// * `oauth_providers` - HashMap of OAuth providers keyed by provider name
pub struct AppState {
    /// OAuth providers configured for the application
    pub oauth_providers: HashMap<String, Arc<dyn OAuthProvider>>,
}

/// HTTP server struct that holds port and shared state
///
/// This struct represents the HTTP server instance and contains
/// the configuration needed to run the server.
///
/// # Fields
///
/// * `port` - Port number to listen on
/// * `app_state` - Shared application state for request handlers
pub struct Server {
    /// Port number to listen on
    pub port: u16,
    /// Shared application state for request handlers
    pub app_state: Arc<AppState>,
}

impl Server {
    /// Creates a new HTTP server instance
    ///
    /// This constructor creates a new server instance with the specified
    /// port and application state.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to listen on
    /// * `app_state` - Shared state containing the OAuth providers
    ///
    /// # Returns
    ///
    /// Returns a new `Server` instance
    pub fn new(port: u16, app_state: Arc<AppState>) -> Self {
        Server { port, app_state }
    }

    /// Runs the HTTP server with configured routes and middleware
    ///
    /// This method starts the HTTP server with the following configuration:
    ///
    /// ## Routes
    ///
    /// - `GET /authorize` - Initiates OAuth flow
    /// - `GET /callback` - Handles OAuth callback
    /// - `GET /health` - Health check endpoint
    /// - `GET /` - Home page with provider buttons
    ///
    /// ## Middleware
    ///
    /// - **Session Management**: Uses MokaStore with 1-hour TTL
    /// - **CORS**: Allows any origin, GET and POST methods, all headers
    /// - **Tracing**: Request logging with method and path information
    pub async fn run(&self) {
        let moka_store = MokaStore::new(Some(20));

        // Configure session middleware
        let session_layer = SessionManagerLayer::new(moka_store)
            .with_same_site(tower_sessions::cookie::SameSite::Lax)
            .with_secure(true)
            .with_expiry(Expiry::OnInactivity(CACHE_TTL));

        let cors = CorsLayer::new()
            // allow `GET` and `POST` when accessing the resource
            .allow_methods(vec![Method::GET, Method::POST])
            // allow requests from any origin
            .allow_origin(Any)
            .allow_headers(AllowHeaders::any());

        // Set up API routes and attach middleware
        let app = Router::new()
            .route("/authorize", get(oauth_authorize))
            .route("/callback", get(oauth_callback))
            .route("/health", get(health_check))
            .route("/", get(home_page))
            .layer(session_layer)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                }),
            )
            .with_state(Arc::clone(&self.app_state));

        let address = format!("0.0.0.0:{}", self.port);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();

        axum::serve(listener, app).await.unwrap();
    }
}
