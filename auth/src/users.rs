use async_oidc_jwt_validator::OidcValidator;
use axum::http::header::AUTHORIZATION;
use axum_login::{tracing, AuthUser, AuthnBackend, UserId};
use log::{debug, error};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError}, url::Url, AuthorizationCode, CsrfToken, EndpointNotSet, EndpointSet,
    Scope,
    TokenResponse,
};
use serde::Deserialize;
use serde_derive::Serialize;
use sqlx::{FromRow, SqlitePool};

// prevent logging the access token
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("email", &self.email)
            .field("access_token", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.access_token.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum Credentials {
    Bearer(BearerCreds),
    OAuth(OAuthCreds),
}

#[derive(Debug, Clone, Deserialize)]
pub struct BearerCreds {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCreds {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub email: String,
}

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    pub name: String,
    pub email: String,
    pub access_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<<reqwest::Client as oauth2::AsyncHttpClient<'static>>::Error>),

    #[error(transparent)]
    JWT(jsonwebtoken::errors::Error),
}

pub type BasicClientSet =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Clone)]
pub struct Backend {
    db: SqlitePool,
    client: BasicClientSet,
    http_client: reqwest::Client,
    userinfo_endpoint: String,
    validator: OidcValidator,
}

impl Backend {
    pub async fn new(
        db: SqlitePool,
        client: BasicClientSet,
        userinfo_endpoint: String,
        validator: OidcValidator,
    ) -> Self {
        let http_client: reqwest::Client = reqwest::ClientBuilder::new()
            // following redirects opens the client up to SSRF vulnerabilities
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");
        Self {
            db,
            client,
            http_client,
            userinfo_endpoint,
            validator,
        }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .url()
    }
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        tracing::debug!("credentials: {:#?}", creds);
        match creds {
            Credentials::Bearer(bearer_creds) => {
                match self
                    .validator
                    .validate::<Claims>(bearer_creds.token.as_str())
                    .await
                {
                    Ok(claims) => {
                        debug!("Valid token for sub: {}", claims.sub);
                        Ok(None)
                    }
                    Err(e) => {
                        error!("Bearer token validation failed: {}", e);
                        debug!("Bearer token validation failed: {}", e);
                        Err(BackendError::JWT(e))
                    }
                }
            }
            Credentials::OAuth(oauth_creds) => {
                // ensure the CSRF state has not been tampered with
                if oauth_creds.old_state.secret() != oauth_creds.new_state.secret() {
                    return Ok(None);
                };

                // process authorization code, expecting a token response back
                let access_token = self
                    .client
                    .exchange_code(AuthorizationCode::new(oauth_creds.code))
                    .request_async(&self.http_client)
                    .await
                    .map_err(Self::Error::OAuth2)?
                    .access_token()
                    .secret()
                    .to_string();

                // use access token to request user info
                let user_info = reqwest::Client::new()
                    .get(&self.userinfo_endpoint)
                    .header(AUTHORIZATION.as_str(), format!("Bearer {}", access_token))
                    .send()
                    .await
                    .map_err(Self::Error::Reqwest)?
                    .json::<UserInfo>()
                    .await
                    .map_err(Self::Error::Reqwest)?;

                // persist user in our database so we can use `get_user`
                let user = sqlx::query_as(
                    r#"
                        insert into users (name, email, access_token)
                        values (?, ?, ?)
                        on conflict(email) do update
                        set access_token = excluded.access_token
                        returning *
                        "#,
                )
                .bind(user_info.name)
                .bind(user_info.email)
                .bind(access_token)
                .fetch_one(&self.db)
                .await
                .map_err(Self::Error::Sqlx)?;

                Ok(Some(user))
            }
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Self::Error::Sqlx)
    }
}

// type alias for AuthSession
pub type AuthSession = axum_login::AuthSession<Backend>;
