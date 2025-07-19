# OAuth 2.0 Server

A robust, production-ready OAuth 2.0 server built in Rust that provides secure authentication flows for multiple OAuth providers. This server implements the OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) for enhanced security.

## 🚀 Project Overview

This OAuth 2.0 server is designed to be a standalone authentication service that can be easily integrated into any application requiring OAuth authentication. It provides a clean, secure, and extensible solution for handling OAuth flows with multiple providers.

### Key Features

- **🔐 Secure OAuth 2.0 Implementation**: Full OAuth 2.0 Authorization Code flow with PKCE
- **🛡️ Security First**: CSRF protection, session management, and secure token handling
- **🌐 Multiple Providers**: Google, GitHub, Twitter, Discord, and Spotify support
- **⚡ High Performance**: Built with Rust and Axum for excellent performance
- **🔧 Extensible Architecture**: Easy to add new OAuth providers
- **📊 Health Monitoring**: Built-in health checks and logging
- **🐳 Docker Ready**: Complete Docker support for easy deployment
- **📝 Comprehensive Documentation**: Well-documented codebase with examples

## 🎯 Use Cases

### 1. **Frontend Application Authentication**

Perfect for single-page applications (SPAs) that need secure user authentication without managing OAuth complexity on the frontend.

### 2. **Microservices Architecture**

Serve as a dedicated authentication service in a microservices environment, providing centralized OAuth handling.

### 3. **API Gateway Integration**

Use as an authentication layer in API gateways to handle OAuth flows before routing requests to backend services.

### 4. **Development and Testing**

Great for development environments where you need to test OAuth integrations without setting up complex authentication systems.

### 5. **Legacy System Modernization**

Add modern OAuth authentication to existing applications without major refactoring.

## 🏗️ Architecture

### Core Components

- **OAuth Providers**: Modular provider implementations for each OAuth service
- **Session Management**: Secure session handling with tower-sessions
- **HTTP Server**: High-performance server built with Axum
- **Configuration Management**: Flexible configuration via TOML files or environment variables
- **Error Handling**: Comprehensive error handling and logging

### Security Features

- **PKCE (Proof Key for Code Exchange)**: Prevents authorization code interception attacks
- **CSRF Protection**: Random state tokens for each OAuth flow
- **Session Security**: Secure session storage with configurable TTL
- **HTTPS Ready**: Designed for production deployment with SSL/TLS

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+
- Cargo
- Docker (optional)

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd oauth2.0
```

### 2. Configure OAuth Providers

Create a `Settings.toml` file with your OAuth provider configurations:

```toml
port = 4427

[oauth.google]
client_id = "your-google-client-id"
client_secret = "your-google-client-secret"
auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://www.googleapis.com/oauth2/v3/token"
redirect_uri = "http://localhost:4427/callback"
user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"

[oauth.github]
client_id = "your-github-client-id"
client_secret = "your-github-client-secret"
auth_url = "https://github.com/login/oauth/authorize"
token_url = "https://github.com/login/oauth/access_token"
redirect_uri = "http://localhost:4427/callback"
user_info_url = "https://api.github.com/user"

# Add other providers as needed
```

### 3. Run the Server

```bash
# Development
cargo run

# Production
cargo build --release
./target/release/oauth-server
```

The server will start on `http://localhost:4427`

### 4. Test the OAuth Flow

Visit `http://localhost:4427/` to see the OAuth provider buttons and test the authentication flow.

## 📚 API Documentation

### Endpoints

| Endpoint     | Method | Description                                                       |
| ------------ | ------ | ----------------------------------------------------------------- |
| `/`          | GET    | Home page with OAuth provider buttons                             |
| `/authorize` | GET    | Initiates OAuth flow (requires `provider` query param)            |
| `/callback`  | GET    | OAuth callback handler (requires `code` and `state` query params) |
| `/health`    | GET    | Health check endpoint                                             |

### OAuth Flow

1. **Initiate Flow**: `GET /authorize?provider=google`
2. **User Authorization**: User is redirected to the OAuth provider
3. **Callback Processing**: Provider redirects back to `/callback`
4. **User Information**: Returns user data in JSON format

### Example Response

```json
{
  "user_id": "user@example.com",
  "provider": "google"
}
```

## 🔧 Configuration

### Environment Variables

For production deployments, you can use environment variables:

```bash
export PORT=4427
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
export GOOGLE_REDIRECT_URI="https://yourdomain.com/callback"
```

## 🛠️ Development

### Project Structure

```
src/
├── main.rs              # Application entry point
├── settings.rs          # Configuration management
├── traits.rs            # OAuth provider traits
├── primitives.rs        # Core data structures
├── types.rs             # Type definitions
├── providers/           # OAuth provider implementations
│   ├── mod.rs          # Provider registry
│   ├── google.rs       # Google OAuth
│   ├── github.rs       # GitHub OAuth
│   ├── twitter.rs      # Twitter OAuth
│   ├── discord.rs      # Discord OAuth
│   └── spotify.rs      # Spotify OAuth
└── server/             # HTTP server components
    ├── mod.rs          # Server module
    ├── server.rs       # Server implementation
    ├── handlers.rs     # Request handlers
    └── errors.rs       # Error handling
```

### Adding New OAuth Providers

1. **Create Provider Implementation**:

   ```rust
   // src/providers/new_provider.rs
   pub struct NewProvider { /* ... */ }
   impl OAuthProvider for NewProvider { /* ... */ }
   pub struct NewProviderFactory;
   impl OAuthProviderFactory for NewProviderFactory { /* ... */ }
   ```

2. **Register in Provider Registry**:

   ```rust
   // In src/providers/mod.rs
   m.insert("new_provider", Arc::new(NewProviderFactory));
   ```

3. **Add Configuration**:
   ```toml
   [oauth.new_provider]
   client_id = "..."
   client_secret = "..."
   # ... other required fields
   ```

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

## 🤝 Contributing

We welcome contributions from the community! This project is completely open to improvements, new features, bug fixes, and other contributions.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**:
   - Add new OAuth providers
   - Improve security features
   - Enhance documentation
   - Add tests
   - Optimize performance
   - Fix bugs
4. **Test your changes**: `cargo test`
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to the branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Development Guidelines

- Follow Rust coding conventions
- Add comprehensive documentation
- Include tests for new features
- Update documentation when adding new features
- Ensure all tests pass before submitting PR

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://rust-lang.org/) and [Axum](https://github.com/tokio-rs/axum)
- OAuth 2.0 implementation using [oauth2](https://github.com/ramosbugs/oauth2-rs)
- Session management with [tower-sessions](https://github.com/maxcountryman/tower-sessions)
- HTTP client using [reqwest](https://github.com/seanmonstar/reqwest)
