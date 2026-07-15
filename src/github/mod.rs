//! GitHub API helpers (user-to-server calls only; we never mint JWTs or
//! installation tokens — see docs/DESIGN.md "GitHub App").
//!
//! All base URLs come from [`AppConfig`](crate::state::AppConfig) so tests
//! can point them at a mock server.
//!
//! Security note: none of these types derive `Debug`, and no response body
//! that could contain a token is ever logged.

pub mod oauth;

use cja::color_eyre::eyre::eyre;
use serde::Deserialize;

use crate::state::AppState;

/// Where we send users who have not installed the app on any account yet.
pub const INSTALL_URL: &str = "https://github.com/apps/pending-review-notifier/installations/new";

const GITHUB_JSON: &str = "application/vnd.github+json";

pub struct Viewer {
    pub login: String,
    pub database_id: i64,
}

pub struct UserInstallation {
    pub id: i64,
    pub account_login: String,
    pub repository_selection: String,
}

/// `query { viewer { login databaseId } }` as the user.
pub async fn fetch_viewer(state: &AppState, access_token: &str) -> cja::Result<Viewer> {
    #[derive(Deserialize)]
    struct GraphQlResponse {
        data: Option<Data>,
    }
    #[derive(Deserialize)]
    struct Data {
        viewer: ViewerNode,
    }
    #[derive(Deserialize)]
    struct ViewerNode {
        login: String,
        #[serde(rename = "databaseId")]
        database_id: i64,
    }

    let response = state
        .http
        .post(format!("{}/graphql", state.config.github_api_base))
        .bearer_auth(access_token)
        .json(&serde_json::json!({ "query": "query { viewer { login databaseId } }" }))
        .send()
        .await?
        .error_for_status()?;

    let body: GraphQlResponse = response.json().await?;
    let viewer = body
        .data
        .ok_or_else(|| eyre!("GraphQL viewer query returned no data"))?
        .viewer;

    Ok(Viewer {
        login: viewer.login,
        database_id: viewer.database_id,
    })
}

/// `GET /user/emails`; picks the primary verified address, else the first.
pub async fn fetch_primary_email(state: &AppState, access_token: &str) -> cja::Result<String> {
    #[derive(Deserialize)]
    struct EmailEntry {
        email: String,
        primary: bool,
        verified: bool,
    }

    let response = state
        .http
        .get(format!("{}/user/emails", state.config.github_api_base))
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, GITHUB_JSON)
        .send()
        .await?
        .error_for_status()?;

    let emails: Vec<EmailEntry> = response.json().await?;
    let email = emails
        .iter()
        .find(|e| e.primary && e.verified)
        .or_else(|| emails.first())
        .ok_or_else(|| eyre!("GitHub returned no email addresses for the user"))?;

    Ok(email.email.clone())
}

/// `GET /user/installations` — installations the user token can see.
pub async fn fetch_user_installations(
    state: &AppState,
    access_token: &str,
) -> cja::Result<Vec<UserInstallation>> {
    #[derive(Deserialize)]
    struct InstallationsResponse {
        installations: Vec<InstallationEntry>,
    }
    #[derive(Deserialize)]
    struct InstallationEntry {
        id: i64,
        account: Account,
        repository_selection: String,
    }
    #[derive(Deserialize)]
    struct Account {
        login: String,
    }

    let response = state
        .http
        .get(format!(
            "{}/user/installations",
            state.config.github_api_base
        ))
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, GITHUB_JSON)
        .send()
        .await?
        .error_for_status()?;

    let body: InstallationsResponse = response.json().await?;
    Ok(body
        .installations
        .into_iter()
        .map(|i| UserInstallation {
            id: i.id,
            account_login: i.account.login,
            repository_selection: i.repository_selection,
        })
        .collect())
}

/// `DELETE /applications/{client_id}/grant` — revoke the app authorization.
///
/// Treats 404/422 as success (grant already gone / token already invalid);
/// anything else is an error the caller may choose to log and ignore, since
/// local deletion must not be blockable by GitHub flakiness.
pub async fn revoke_grant(state: &AppState, access_token: &str) -> cja::Result<()> {
    let response = state
        .http
        .delete(format!(
            "{}/applications/{}/grant",
            state.config.github_api_base, state.config.github_client_id
        ))
        .basic_auth(
            &state.config.github_client_id,
            Some(&state.config.github_client_secret),
        )
        .header(reqwest::header::ACCEPT, GITHUB_JSON)
        .json(&serde_json::json!({ "access_token": access_token }))
        .send()
        .await?;

    match response.status().as_u16() {
        204 | 404 | 422 => Ok(()),
        status => Err(eyre!("grant revocation failed with HTTP {status}")),
    }
}
