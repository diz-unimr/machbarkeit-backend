use config::{Config, ConfigError, Environment, File};
use serde_derive::Deserialize;

#[derive(Default, Deserialize, Clone)]
pub(crate) struct AppConfig {
    pub(crate) log_level: String,
    pub(crate) base_url: String,
    pub(crate) auth: Option<Auth>,
    pub(crate) cors: Option<Cors>,
    pub(crate) mdr: Option<Mdr>,
    pub(crate) session: Session,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Session {
    pub(crate) lifetime: i64,
    pub(crate) cross_domain: bool,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Auth {
    pub(crate) oidc: Option<Oidc>,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Oidc {
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) auth_endpoint: Option<String>,
    pub(crate) token_endpoint: Option<String>,
    pub(crate) userinfo_endpoint: Option<String>,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Cors {
    pub(crate) allow_origin: Option<String>,
}

#[derive(Default, Deserialize, Clone)]
pub(crate) struct Mdr {
    pub(crate) endpoint: String,
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
