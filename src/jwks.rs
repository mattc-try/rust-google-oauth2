use once_cell::sync::OnceCell;
use jsonwebtoken::jwk::JwkSet;
use anyhow::Result;
use serde_json::from_str;

static JWKS: OnceCell<JwkSet> = OnceCell::new();
use tokio::time::{interval, Duration};


/// Fetches and updates the JSON Web Key Set (JWKS) from Google's public endpoint.
/// This function runs asynchronously and ensures only one update at a time.
pub async fn fetch_jwks() -> Result<()> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch JWKS: {}", e))?;
    
    let res_text = res.text().await?;
    let jwks: JwkSet = serde_json::from_str(&res_text)
        .map_err(|e| anyhow::anyhow!("Failed to parse JWKS: {}", e))?;

    JWKS.set(jwks)
        .map_err(|_| anyhow::anyhow!("JWKS already initialized"))?;
    Ok(())
}

/// Retrieves the JWK corresponding to the given Key ID (kid).
/// Returns None if the key is not found.
pub fn get_jwk(kid: &str) -> Option<&jsonwebtoken::jwk::Jwk> {
    JWKS.get().and_then(|jwks| {
        jwks.keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid))
    })
}

/// Starts an asynchronous task that periodically refreshes the JWKS every hour.
/// Logs errors if refreshing fails.
pub async fn start_jwks_refresh() {
    let mut interval = interval(Duration::from_secs(3600)); // Refresh every hour
    loop {
        interval.tick().await;
        if let Err(e) = fetch_jwks().await {
            log::error!("Failed to refresh JWKS: {}", e);
        }
    }
}