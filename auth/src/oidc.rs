use anyhow::anyhow;
use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
}

impl DiscoveryDocument {
    pub async fn new(issuer_url: &str) -> Result<Self, anyhow::Error> {
        Ok(discover(issuer_url).await?)
    }
}

async fn discover(issuer_url: &str) -> Result<DiscoveryDocument, anyhow::Error> {
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer_url);

    log::debug!("Fetching OpenID Connect discovery from: {}", discovery_url);

    let response = reqwest::get(&discovery_url)
        .await
        .map_err(|e| anyhow!("Failed to fetch OIDC discovery document: {}", e))?;

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if !content_type.starts_with("application/json") {
        return Err(anyhow!(
            "Unexpected Content-Type: '{}', expected 'application/json'",
            content_type
        ));
    }

    if !response.status().is_success() {
        return Err(anyhow!(
            "OIDC discovery request failed with status: {}",
            response.status()
        ));
    }

    let discovery: DiscoveryDocument = response
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse OIDC discovery response: {}", e))?;

    Ok(discovery)
}
