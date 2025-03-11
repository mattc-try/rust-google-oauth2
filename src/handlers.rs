use warp::{Filter, http::Uri, Reply};
use serde::Deserialize;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, basic::BasicClient, TokenResponse,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use rand::RngCore;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tera::Tera;
use crate::jwks;
// use serde_urlencoded;



#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: String, // Contains JWT with user information
    pub scope: Option<String>,
}

// Lazy-initialized state tracking for OAuth flow
lazy_static! {
    static ref STATES: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    static ref CODE_VERIFIERS: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String, // Authorization code received from OAuth provider
    state: String, // CSRF protection state
}

// Handler for initiating OAuth login
pub async fn login_handler() -> Result<impl Reply, warp::Rejection> {
    let state = generate_state(); // Generate a unique state parameter for CSRF protection
    let code_verifier = PkceCodeVerifier::new(generate_code_verifier());
    let code_challenge = PkceCodeChallenge::from_code_verifier_sha256(&code_verifier);

    println!("Stored state: {}", state);
    STATES.lock().await.push(state.clone()); // Store state to validate later
    CODE_VERIFIERS.lock().await.insert(
        state.clone(),
        code_verifier.secret().to_string(), // Store code verifier for PKCE validation
    );

    let client = get_oauth_client();
    let (auth_url, _) = client
        .authorize_url(|| CsrfToken::new(state.clone())) // Pass the state to OAuth provider
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(code_challenge)
        .url();

    let uri: Uri = auth_url.as_str().parse().unwrap();
    Ok(warp::redirect::found(uri))
}

pub async fn callback_handler(
    query: CallbackQuery,
    tera: Arc<Tera>,
) -> Result<impl Reply, warp::Rejection> {
    println!("Received state: {}", query.state); // Debugging

    // Validate the state parameter to prevent CSRF attacks
    if !validate_state(&query.state).await {
        return Err(warp::reject::custom(Error::InvalidState));
    }

    // Retrieve the code verifier associated with the state for PKCE validation
    let code_verifier_secret = CODE_VERIFIERS.lock().await.remove(&query.state)
        .ok_or_else(|| warp::reject::custom(Error::MissingCodeVerifier))?;

    // Manually request the token from Google's token endpoint
    let client = reqwest::Client::new();
    let token_url = "https://oauth2.googleapis.com/token";

    let params = [
        ("code", query.code),
        ("client_id", std::env::var("CLIENTID").expect("CLIENTID not set")),
        ("client_secret", std::env::var("CLIENTSECRET").expect("CLIENTSECRET not set")),
        ("redirect_uri", "http://localhost:8080/callback".to_string()),
        ("grant_type", "authorization_code".to_string()),
        ("code_verifier", code_verifier_secret), // include the code verifier for PKCE
    ];

    // Send the POST request to Google's token endpoint to exchange code for tokens
    let res = client.post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|_| warp::reject::custom(Error::TokenExchangeFailed))?;

    // Parse the response into our custom GoogleTokenResponse struct
    let token_response: GoogleTokenResponse = res.json()
        .await
        .map_err(|_| warp::reject::custom(Error::InvalidTokenResponse))?;

    // Extract the ID token from the response
    let id_token = token_response.id_token;

    // Validate the JWT and extract user info
    let claims = validate_jwt(&id_token)?;
    let (name, email) = extract_user_info(&claims)?;

    // Render the template with the user's name and email
    let mut context = tera::Context::new();
    context.insert("Name", &name);
    context.insert("Email", &email);

    let html = tera.render("callback.html", &context)
        .map_err(|_| warp::reject::custom(Error::TemplateError))?;

    Ok(warp::reply::html(html))
}

fn generate_state() -> String {
    let mut state = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut state);
    hex::encode(state)
}

fn generate_code_verifier() -> String {
    let mut verifier = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut verifier);
    URL_SAFE_NO_PAD.encode(&verifier)
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&result)
}

// Retrieve the OAuth client configuration
fn get_oauth_client() -> BasicClient {
    BasicClient::new(
        ClientId::new(std::env::var("CLIENTID").expect("CLIENTID not set")),
        Some(ClientSecret::new(std::env::var("CLIENTSECRET").expect("CLIENTSECRET not set"))),
        oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()).unwrap(),
        Some(oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080/callback".to_string()).unwrap())
    .set_auth_type(oauth2::AuthType::RequestBody)
}

// Validate the state parameter to prevent CSRF attacks
async fn validate_state(state: &str) -> bool {
    let mut states = STATES.lock().await; // Use .await
    println!("Stored states: {:?}", states); // Debugging
    if let Some(index) = states.iter().position(|s| s == state) {
        states.remove(index);
        true
    } else {
        false
    }
}

// Validate and decode a JWT token
fn validate_jwt(token: &str) -> Result<Value, warp::Rejection> {
    let header = decode_header(token)
        .map_err(|e| warp::reject::custom(Error::JwtError(e)))?;
    
    let kid = header.kid.ok_or(Error::MissingKid)?;
    let jwk = jwks::get_jwk(&kid).ok_or(Error::KeyNotFound)?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| warp::reject::custom(Error::JwtError(e)))?;

    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = true; // checks exp validation

    let token_data = decode::<Value>(
        token,
        &decoding_key,
        &validation
    ).map_err(|e| warp::reject::custom(Error::JwtError(e)))?;

    validate_iss(&token_data.claims)?;
    validate_aud(&token_data.claims)?;

    Ok(token_data.claims)
}

fn validate_iss(claims: &Value) -> Result<(), warp::Rejection> {
    let iss = claims["iss"].as_str().ok_or(Error::InvalidIss)?;
    if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
        return Err(Error::InvalidIssuer.into());
    }
    Ok(())
}

fn validate_aud(claims: &Value) -> Result<(), warp::Rejection> {
    let aud = claims["aud"].as_str().ok_or(Error::InvalidAud)?;
    let client_id = std::env::var("CLIENTID").map_err(|_| Error::ClientIdNotSet)?;
    if aud != client_id {
        return Err(Error::InvalidAudience.into());
    }
    Ok(())
}

fn extract_user_info(claims: &Value) -> Result<(String, String), warp::Rejection> {
    let name = claims["given_name"].as_str().unwrap_or("Unknown").to_string();
    let email = claims["email"].as_str().unwrap_or("Unknown").to_string();
    Ok((name, email))
}

// Middleware for injecting Tera templating engine into Warp filters
pub fn with_tera(
    tera: Arc<Tera>,
) -> impl Filter<Extract = (Arc<Tera>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || tera.clone())
}

#[derive(Debug)]
enum Error {
    InvalidState,
    MissingCodeVerifier,
    TokenExchangeFailed,
    InvalidIdToken,
    TemplateError,
    MissingKid,
    KeyNotFound,
    InvalidIss,
    InvalidAud,
    ClientIdNotSet,
    InvalidExp,
    InvalidIssuer,
    InvalidAudience,
    TokenExpired,
    JwtError(jsonwebtoken::errors::Error),
    JsonError,
    InvalidTokenResponse,
}

impl warp::reject::Reject for Error {}