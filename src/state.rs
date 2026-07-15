use cja::server::cookies::CookieKey;
use color_eyre::eyre::Context as _;
use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::crypto::TokenCrypto;

/// GitHub requires a User-Agent on every API request.
pub const USER_AGENT: &str = "pending-review-notifier (coreyja-studio)";

/// Application configuration, read from the environment at startup.
#[derive(Clone)]
pub struct AppConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    /// Base64-encoded 32-byte key for XChaCha20-Poly1305 token encryption.
    /// Parsed into [`AppState::crypto`] at startup (fails fast if invalid).
    pub token_enc_key: String,
    pub base_url: String,
    /// REST + GraphQL API base (default `https://api.github.com`).
    /// Overridable so tests can point at a mock server.
    pub github_api_base: String,
    /// OAuth web-flow base (default `https://github.com`).
    pub github_oauth_base: String,
}

impl AppConfig {
    pub fn from_env() -> cja::Result<Self> {
        Ok(Self {
            github_client_id: std::env::var("GITHUB_CLIENT_ID")
                .wrap_err("Missing GITHUB_CLIENT_ID")?,
            github_client_secret: std::env::var("GITHUB_CLIENT_SECRET")
                .wrap_err("Missing GITHUB_CLIENT_SECRET")?,
            token_enc_key: std::env::var("TOKEN_ENC_KEY").wrap_err("Missing TOKEN_ENC_KEY")?,
            base_url: std::env::var("APP_BASE_URL").wrap_err("Missing APP_BASE_URL")?,
            github_api_base: std::env::var("GITHUB_API_BASE")
                .unwrap_or_else(|_| "https://api.github.com".to_string()),
            github_oauth_base: std::env::var("GITHUB_OAUTH_BASE")
                .unwrap_or_else(|_| "https://github.com".to_string()),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cookie_key: CookieKey,
    pub config: AppConfig,
    /// Encrypts/decrypts GitHub tokens at rest.
    pub crypto: TokenCrypto,
    /// Shared HTTP client for all GitHub calls (sets the required User-Agent).
    pub http: reqwest::Client,
}

impl AppState {
    pub async fn from_env() -> cja::Result<Self> {
        let config = AppConfig::from_env()?;

        // Fail fast on a bad key rather than at the first token write.
        let crypto = TokenCrypto::from_base64_key(&config.token_enc_key)?;

        let database_url = std::env::var("DATABASE_URL").wrap_err("Missing DATABASE_URL")?;
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .wrap_err("Failed to connect to Postgres")?;

        sqlx::migrate!()
            .run(&db)
            .await
            .wrap_err("Failed to run migrations")?;

        let cookie_key = CookieKey::from_env_or_generate()?;

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .wrap_err("Failed to build HTTP client")?;

        Ok(Self {
            db,
            cookie_key,
            config,
            crypto,
            http,
        })
    }
}

impl cja::app_state::AppState for AppState {
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn db(&self) -> &PgPool {
        &self.db
    }

    fn cookie_key(&self) -> &CookieKey {
        &self.cookie_key
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use base64::Engine as _;

    /// A valid base64-encoded 32-byte key for tests.
    pub fn test_enc_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([0x42u8; 32])
    }

    pub fn test_config() -> AppConfig {
        AppConfig {
            github_client_id: "test-client-id".to_string(),
            github_client_secret: "test-client-secret".to_string(),
            token_enc_key: test_enc_key(),
            base_url: "https://prn.test".to_string(),
            // `.invalid` is guaranteed unresolvable — a test that
            // accidentally makes a real HTTP call fails loudly.
            github_api_base: "https://api.github.invalid".to_string(),
            github_oauth_base: "https://github.invalid".to_string(),
        }
    }

    pub fn test_state(db: PgPool, config: AppConfig) -> AppState {
        AppState {
            db,
            cookie_key: CookieKey::generate(),
            crypto: TokenCrypto::from_base64_key(&config.token_enc_key)
                .expect("test key must be valid"),
            http: reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .build()
                .expect("test HTTP client must build"),
            config,
        }
    }

    /// AppState whose pool is created lazily and never actually connects —
    /// for router tests whose routes never touch the DB.
    pub fn lazy_test_state() -> AppState {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/prn_test_never_connected")
            .expect("lazy pool creation should not require a running database");
        test_state(db, test_config())
    }
}
