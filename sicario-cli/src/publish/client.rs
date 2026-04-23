//! Cloud publish client — authenticated upload of scan results to Sicario Cloud API.
//!
//! Requirements: 21.3, 21.4, 21.5, 21.6

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::engine::vulnerability::Finding;

/// Metadata attached to every published scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub repository: String,
    pub branch: String,
    pub commit_sha: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub rules_loaded: usize,
    pub files_scanned: usize,
    pub language_breakdown: HashMap<String, usize>,
    pub tags: Vec<String>,
}

/// A complete scan report payload for the Cloud API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
}

/// Resolve the Sicario Cloud API base URL.
///
/// Checks `SICARIO_CLOUD_URL` env var, defaults to `https://flexible-terrier-680.convex.site`.
pub fn resolve_cloud_url() -> String {
    std::env::var("SICARIO_CLOUD_URL")
        .unwrap_or_else(|_| "https://flexible-terrier-680.convex.site".to_string())
}

/// Client for publishing scan results to the Sicario Cloud API.
pub struct PublishClient {
    cloud_url: String,
    auth_token: String,
    http: reqwest::blocking::Client,
    org_id: Option<String>,
}

impl PublishClient {
    /// Create a new publish client with the given cloud URL and auth token.
    pub fn new(cloud_url: String, auth_token: String) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            cloud_url,
            auth_token,
            http,
            org_id: None,
        })
    }

    /// Set the organization ID to include as `X-Sicario-Org` header on requests.
    pub fn with_org(mut self, org_id: Option<String>) -> Self {
        self.org_id = org_id;
        self
    }

    /// Upload a scan report to the Cloud API.
    ///
    /// POSTs the report to `POST /api/v1/scans`.
    pub fn publish(&self, report: &ScanReport) -> Result<PublishResponse> {
        let url = format!("{}/api/v1/scans", self.cloud_url.trim_end_matches('/'));

        let mut request = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("Content-Type", "application/json");

        if let Some(ref org) = self.org_id {
            request = request.header("X-Sicario-Org", org.as_str());
        }

        let resp = request.json(report).send();

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                bail!(
                    "Could not reach Sicario Cloud API at {}: {e}\n\
                     Scan results were NOT published. Your local scan is unaffected.",
                    self.cloud_url
                );
            }
        };

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            bail!(
                "Cloud session expired or invalid. Run `sicario login` to re-authenticate.\n\
                 Scan results were NOT published."
            );
        }

        if !resp.status().is_success() {
            bail!(
                "Cloud publish failed with status {}. Scan results were NOT published.",
                resp.status()
            );
        }

        let publish_resp: PublishResponse = resp.json().unwrap_or(PublishResponse {
            scan_id: String::new(),
            dashboard_url: None,
        });

        Ok(publish_resp)
    }
}

/// Response from the Cloud API after a successful publish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResponse {
    pub scan_id: String,
    pub dashboard_url: Option<String>,
}

/// Collect git metadata (repository, branch, commit SHA) from the current directory.
///
/// Returns `(repository, branch, commit_sha)`. Falls back to empty strings if
/// git info is unavailable.
pub fn collect_git_metadata() -> (String, String, String) {
    let repo = match git2::Repository::discover(".") {
        Ok(r) => r,
        Err(_) => return (String::new(), String::new(), String::new()),
    };

    let repository = repo
        .find_remote("origin")
        .ok()
        .and_then(|r| r.url().map(|u| u.to_string()))
        .unwrap_or_default();

    let head = match repo.head() {
        Ok(h) => h,
        Err(_) => return (repository, String::new(), String::new()),
    };

    let branch = head
        .shorthand()
        .unwrap_or("")
        .to_string();

    let commit_sha = head
        .target()
        .map(|oid| oid.to_string())
        .unwrap_or_default();

    (repository, branch, commit_sha)
}
