use cja::server::cookies::CookieKey;
use color_eyre::eyre::Context as _;
use sqlx::{PgPool, postgres::PgPoolOptions};

/// Application configuration, read from the environment at startup.
///
/// The fields are unread until the OAuth + sync PRs land; reading them from
/// the environment now keeps deploy configuration honest from day one.
#[allow(dead_code)]
#[derive(Clone)]
pub struct AppConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    /// Base64-encoded 32-byte key for XChaCha20-Poly1305 token encryption.
    pub token_enc_key: String,
    pub base_url: String,
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
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cookie_key: CookieKey,
    // Unread until the OAuth + sync PRs land.
    #[allow(dead_code)]
    pub config: AppConfig,
}

impl AppState {
    pub async fn from_env() -> cja::Result<Self> {
        let config = AppConfig::from_env()?;

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

        Ok(Self {
            db,
            cookie_key,
            config,
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
