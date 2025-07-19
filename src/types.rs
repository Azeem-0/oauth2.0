use oauth2::{
    basic::{BasicErrorResponseType, BasicTokenType},
    Client, EmptyExtraTokenFields, EndpointNotSet, EndpointSet, RevocationErrorResponseType,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse,
};

/// OAuth client type alias for the configured OAuth 2.0 client
///
/// This type alias defines the specific OAuth client configuration used
/// throughout the application. It uses the standard OAuth 2.0 error and
/// token response types with basic authentication.
///
/// # Type Parameters
///
/// The client is configured with:
/// - `StandardErrorResponse<BasicErrorResponseType>` - Standard OAuth error responses
/// - `StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>` - Standard token responses
/// - `StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>` - Token introspection
/// - `StandardRevocableToken` - Token revocation support
/// - `StandardErrorResponse<RevocationErrorResponseType>` - Revocation error responses
/// - `EndpointSet` - Authorization endpoint is configured
/// - `EndpointNotSet` - Device authorization not configured
/// - `EndpointNotSet` - Token introspection not configured
/// - `EndpointNotSet` - Token revocation not configured
/// - `EndpointSet` - Token endpoint is configured
pub type OAuthClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,    // set_auth_uri called
    EndpointNotSet, // device auth not set
    EndpointNotSet, // introspection not set
    EndpointNotSet, // revocation not set
    EndpointSet,    // set_token_uri called
>;
