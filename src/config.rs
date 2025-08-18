use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;

#[derive(Default, Deserialize, Clone)]
pub(crate) struct AppConfig {
    pub(crate) log_level: String,
    pub(crate) base_url: String,
    pub(crate) auth: Option<Auth>,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Auth {
    pub(crate) oidc: Option<Oidc>,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Oidc {
    pub(crate) issuer: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
}

impl AppConfig {
    pub(crate) fn new() -> Result<Self, ConfigError> {
        Config::builder()
            // default config from file
            .add_source(File::with_name("app.yaml"))
            // override values from environment variables
            .add_source(Environment::default().separator("__"))
            .build()?
            .try_deserialize()
    }
}
