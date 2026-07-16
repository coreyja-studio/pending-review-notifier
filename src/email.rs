//! Email sender abstraction.
//!
//! A [`Mailer`] trait with two production implementations:
//! - [`MailPaceSender`] — POSTs to the MailPace API when `MAILPACE_TOKEN` is set.
//! - [`StdoutSender`] — logs the rendered email (dev fallback, no token needed).
//!
//! Security: the MailPace token is never logged. On a failed send, only the
//! HTTP status is logged — never headers or response body (either could echo
//! the token).

use std::sync::Arc;

use async_trait::async_trait;

/// Send an HTML email to a single recipient.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, html_body: &str) -> cja::Result<()>;
}

/// MailPace API sender. Posts JSON to `https://app.mailpace.com/api/v1/send`
/// with the `MailPace-Server-Token` header.
pub struct MailPaceSender {
    http: reqwest::Client,
    token: String,
    from: String,
    url: String,
}

impl MailPaceSender {
    pub fn new(http: reqwest::Client, token: String, from: String) -> Self {
        Self {
            http,
            token,
            from,
            url: "https://app.mailpace.com/api/v1/send".to_string(),
        }
    }

    /// Test-only constructor that allows pointing at a mock server URL.
    #[cfg(test)]
    fn with_url(http: reqwest::Client, token: String, from: String, url: String) -> Self {
        Self {
            http,
            token,
            from,
            url,
        }
    }
}

#[async_trait]
impl Mailer for MailPaceSender {
    async fn send(&self, to: &str, subject: &str, html_body: &str) -> cja::Result<()> {
        let resp = self
            .http
            .post(&self.url)
            .header("MailPace-Server-Token", &self.token)
            .json(&serde_json::json!({
                "from": self.from,
                "to": to,
                "subject": subject,
                "htmlbody": html_body,
            }))
            .send()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("MailPace send request failed: {e}"))?;

        if !resp.status().is_success() {
            tracing::error!(status = %resp.status(), "MailPace send failed");
            return Err(color_eyre::eyre::eyre!(
                "MailPace returned HTTP {}",
                resp.status()
            ));
        }

        Ok(())
    }
}

/// Dev fallback sender — logs the rendered email to tracing.
pub struct StdoutSender;

#[async_trait]
impl Mailer for StdoutSender {
    async fn send(&self, to: &str, subject: &str, html_body: &str) -> cja::Result<()> {
        tracing::info!(to, subject, "Digest email (stdout sender):\n{html_body}");
        Ok(())
    }
}

/// Build the appropriate mailer based on whether `MAILPACE_TOKEN` is set.
///
/// Free function (not on `AppConfig`) because `AppConfig` has no `http` client.
pub fn build_mailer(config: &crate::state::AppConfig, http: reqwest::Client) -> Arc<dyn Mailer> {
    match &config.mailpace_token {
        Some(token) => Arc::new(MailPaceSender::new(
            http,
            token.clone(),
            config.mail_from.clone(),
        )),
        None => Arc::new(StdoutSender),
    }
}

/// Test double — captures sent emails for assertions in `SendDigest` tests.
#[cfg(test)]
#[allow(dead_code)]
pub struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub html_body: String,
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct CapturingSender {
    pub sent: Arc<std::sync::Mutex<Vec<CapturedEmail>>>,
}

#[cfg(test)]
#[async_trait]
impl Mailer for CapturingSender {
    async fn send(&self, to: &str, subject: &str, html_body: &str) -> cja::Result<()> {
        self.sent.lock().unwrap().push(CapturedEmail {
            to: to.to_string(),
            subject: subject.to_string(),
            html_body: html_body.to_string(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn stdout_sender_does_not_error() {
        let sender = StdoutSender;
        sender
            .send("a@b.com", "Subject", "<p>hi</p>")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mailpace_sends_with_token_header_and_json_body() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/send"))
            .and(header("MailPace-Server-Token", "test-token"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let http = reqwest::Client::new();
        let sender = MailPaceSender::with_url(
            http,
            "test-token".to_string(),
            "from@test".to_string(),
            format!("{}/api/v1/send", mock.uri()),
        );

        sender
            .send("to@test", "Your pending reviews", "<p>hi</p>")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mailpace_non_2xx_returns_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/send"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let http = reqwest::Client::new();
        let sender = MailPaceSender::with_url(
            http,
            "test-token".to_string(),
            "from@test".to_string(),
            format!("{}/api/v1/send", mock.uri()),
        );

        let result = sender.send("to@test", "Subject", "<p>hi</p>").await;
        assert!(result.is_err());
    }
}
