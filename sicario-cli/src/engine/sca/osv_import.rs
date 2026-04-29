//! OSV.dev vulnerability import
//!
//! Provides two import strategies:
//! 1. Per-package query via `POST https://api.osv.dev/v1/query` (primary)
//! 2. Bulk ZIP download from GCS (legacy fallback)
//!
//! The per-package query is used during scans to fetch vulnerability data
//! for specific dependencies found in lockfiles.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use super::known_vulnerability::KnownVulnerability;
use super::vuln_db::{owasp_to_str, severity_to_str};
use crate::engine::Severity;

/// OSV.dev REST API endpoint for per-package queries
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// OSV.dev bulk export base URL (legacy fallback)
const OSV_BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";

// ---------------------------------------------------------------------------
// OSV JSON schema (subset we care about)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(rename = "package")]
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

// ---------------------------------------------------------------------------
// OSV query API request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvQueryPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvRecord>,
}

// ---------------------------------------------------------------------------
// Importer
// ---------------------------------------------------------------------------

pub struct OsvImporter {
    conn: Arc<Mutex<Connection>>,
}

impl OsvImporter {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Query OSV.dev for vulnerabilities affecting a specific package+version.
    ///
    /// Calls `POST https://api.osv.dev/v1/query` and upserts all returned
    /// records into the local SQLite cache. Returns the number of records upserted.
    pub fn query_package(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> Result<usize> {
        let request_body = OsvQueryRequest {
            package: OsvQueryPackage {
                name: package_name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: if version.is_empty() {
                None
            } else {
                Some(version.to_string())
            },
        };

        // Enforce a hard 2-second timeout — zero-exfiltration guarantee: network
        // failures must never block or hang the scan pipeline.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .context("Failed to build HTTP client")?;

        let response = match client
            .post(OSV_QUERY_URL)
            .header("Content-Type", "application/json")
            .header("User-Agent", "sicario-cli")
            .json(&request_body)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "OSV query timed out or failed for {}/{}@{} (scan unaffected): {}",
                    ecosystem,
                    package_name,
                    version,
                    e
                );
                return Ok(0);
            }
        };

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV query returned HTTP {} for {}/{}",
                response.status(),
                ecosystem,
                package_name
            );
        }

        let osv_response: OsvQueryResponse = response
            .json()
            .context("Failed to parse OSV query response")?;

        let mut count = 0usize;
        for record in &osv_response.vulns {
            for affected in &record.affected {
                match osv_record_to_known_vulnerability(record, affected) {
                    Ok(kv) => {
                        if self.upsert_kv(&kv).is_ok() {
                            count += 1;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Skipping OSV record {}: {}", record.id, e);
                    }
                }
            }
        }

        Ok(count)
    }

    /// Query OSV.dev for a batch of dependencies and upsert all results.
    /// Returns the total number of records upserted.
    pub fn query_packages(
        &self,
        deps: &[(String, String, String)], // (ecosystem, package_name, version)
    ) -> Result<usize> {
        let mut total = 0usize;
        for (ecosystem, package_name, version) in deps {
            match self.query_package(ecosystem, package_name, version) {
                Ok(count) => total += count,
                Err(e) => {
                    tracing::warn!(
                        "OSV query failed for {}/{}@{}: {}",
                        ecosystem,
                        package_name,
                        version,
                        e
                    );
                }
            }
        }
        Ok(total)
    }

    /// Download and import all advisories for a single ecosystem (bulk ZIP).
    /// This is the legacy fallback approach. Returns the number of records upserted.
    pub fn import_ecosystem(&self, ecosystem: &str) -> Result<usize> {
        let url = format!("{}/{}/all.zip", OSV_BASE_URL, ecosystem);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .context("Failed to build HTTP client")?;

        let response = match client.get(&url).send() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "OSV bulk download timed out or failed for {} (scan unaffected): {}",
                    ecosystem,
                    e
                );
                return Ok(0);
            }
        };

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV download returned HTTP {} for ecosystem {}",
                response.status(),
                ecosystem
            );
        }

        let bytes = response
            .bytes()
            .with_context(|| format!("Failed to read OSV response body for {}", ecosystem))?;

        self.import_zip_bytes(&bytes, ecosystem)
    }

    /// Parse a ZIP archive containing OSV JSON files and upsert each record.
    pub fn import_zip_bytes(&self, zip_bytes: &[u8], ecosystem: &str) -> Result<usize> {
        let cursor = Cursor::new(zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).context("Failed to open OSV ZIP archive")?;

        let mut count = 0usize;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .with_context(|| format!("Failed to read ZIP entry {}", i))?;

            if !file.name().ends_with(".json") {
                continue;
            }

            let mut json_str = String::new();
            file.read_to_string(&mut json_str)
                .with_context(|| format!("Failed to read ZIP entry: {}", file.name()))?;

            match self.import_osv_json(&json_str, ecosystem) {
                Ok(n) => count += n,
                Err(e) => {
                    tracing::debug!("Skipping OSV entry {}: {}", file.name(), e);
                }
            }
        }

        Ok(count)
    }

    /// Parse a single OSV JSON string and upsert into the database.
    pub fn import_osv_json(&self, json_str: &str, _ecosystem: &str) -> Result<usize> {
        let record: OsvRecord =
            serde_json::from_str(json_str).context("Failed to parse OSV JSON")?;

        let mut count = 0usize;

        for affected in &record.affected {
            let kv = osv_record_to_known_vulnerability(&record, affected)?;

            if !self.should_upsert(&kv, record.modified.as_deref())? {
                continue;
            }

            self.upsert_kv(&kv)?;
            count += 1;
        }

        Ok(count)
    }

    /// Determine whether a record should be upserted based on the `modified` timestamp.
    fn should_upsert(&self, kv: &KnownVulnerability, modified: Option<&str>) -> Result<bool> {
        let Some(modified_str) = modified else {
            return Ok(true);
        };

        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let existing: rusqlite::Result<String> = conn.query_row(
            "SELECT last_synced_at FROM known_vulnerabilities
             WHERE package_name = ?1 AND ecosystem = ?2
             AND (cve_id = ?3 OR ghsa_id = ?4)",
            params![kv.package_name, kv.ecosystem, kv.cve_id, kv.ghsa_id,],
            |row| row.get(0),
        );

        match existing {
            Ok(stored_ts) => Ok(modified_str > stored_ts.as_str()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    fn upsert_kv(&self, kv: &KnownVulnerability) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let versions_json = serde_json::to_string(&kv.vulnerable_versions)?;
        let severity_str = severity_to_str(kv.severity);
        let owasp_str = kv.owasp_category.map(owasp_to_str);
        let unique_key = kv.unique_key();

        conn.execute(
            "INSERT OR REPLACE INTO known_vulnerabilities
             (cve_id, ghsa_id, package_name, ecosystem, vulnerable_versions,
              patched_version, summary, severity, owasp_category, last_synced_at, unique_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                kv.cve_id,
                kv.ghsa_id,
                kv.package_name,
                kv.ecosystem,
                versions_json,
                kv.patched_version,
                kv.summary,
                severity_str,
                owasp_str,
                kv.last_synced_at.to_rfc3339(),
                unique_key,
            ],
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn osv_record_to_known_vulnerability(
    record: &OsvRecord,
    affected: &OsvAffected,
) -> Result<KnownVulnerability> {
    let mut cve_id: Option<String> = None;
    let mut ghsa_id: Option<String> = None;

    let all_ids =
        std::iter::once(record.id.as_str()).chain(record.aliases.iter().map(String::as_str));

    for id in all_ids {
        if id.starts_with("CVE-") && cve_id.is_none() {
            cve_id = Some(id.to_string());
        } else if id.starts_with("GHSA-") && ghsa_id.is_none() {
            ghsa_id = Some(id.to_string());
        }
    }

    let mut vulnerable_versions: Vec<String> = Vec::new();
    let mut patched_version: Option<String> = None;

    for range in &affected.ranges {
        if range.range_type != "SEMVER" && range.range_type != "ECOSYSTEM" {
            continue;
        }

        let mut introduced: Option<String> = None;
        let mut fixed: Option<String> = None;

        for event in &range.events {
            if let Some(ref v) = event.introduced {
                if v != "0" {
                    introduced = Some(v.clone());
                }
            }
            if let Some(ref v) = event.fixed {
                fixed = Some(v.clone());
                patched_version = Some(v.clone());
            }
            if let Some(ref v) = event.last_affected {
                let range_str = match &introduced {
                    Some(intro) => format!(">={}, <={}", intro, v),
                    None => format!("<={}", v),
                };
                vulnerable_versions.push(range_str);
            }
        }

        let range_str = match (&introduced, &fixed) {
            (Some(intro), Some(fix)) => format!(">={}, <{}", intro, fix),
            (Some(intro), None) => format!(">={}", intro),
            (None, Some(fix)) => format!("<{}", fix),
            (None, None) => continue,
        };

        if !vulnerable_versions.iter().any(|r| r == &range_str) {
            vulnerable_versions.push(range_str);
        }
    }

    let severity = osv_severity_to_enum(&record.severity);

    let summary = record
        .summary
        .clone()
        .unwrap_or_else(|| format!("Vulnerability in {}", affected.package.name));

    Ok(KnownVulnerability {
        cve_id,
        ghsa_id,
        package_name: affected.package.name.clone(),
        ecosystem: affected.package.ecosystem.clone(),
        vulnerable_versions,
        patched_version,
        summary,
        severity,
        owasp_category: None,
        last_synced_at: Utc::now(),
    })
}

fn osv_severity_to_enum(severities: &[OsvSeverity]) -> Severity {
    for s in severities {
        if s.severity_type == "CVSS_V3" || s.severity_type == "CVSS_V2" {
            if let Some(score) = extract_cvss_base_score(&s.score) {
                return cvss_score_to_severity(score);
            }
        }
    }
    Severity::Medium
}

fn extract_cvss_base_score(score_str: &str) -> Option<f32> {
    if let Ok(v) = score_str.parse::<f32>() {
        return Some(v);
    }
    None
}

fn cvss_score_to_severity(score: f32) -> Severity {
    match score as u8 {
        0 => Severity::Info,
        1..=3 => Severity::Low,
        4..=6 => Severity::Medium,
        7..=8 => Severity::High,
        _ => Severity::Critical,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::known_vulnerability::{CREATE_METADATA_TABLE_SQL, CREATE_TABLE_SQL};
    use super::*;
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn make_conn() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        conn.execute_batch(CREATE_TABLE_SQL).unwrap();
        conn.execute_batch(CREATE_METADATA_TABLE_SQL).unwrap();
        Arc::new(Mutex::new(conn))
    }

    const SAMPLE_OSV_JSON: &str = r#"{
        "id": "GHSA-jfh8-c2jp-hdp9",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command injection in lodash",
        "modified": "2023-01-01T00:00:00Z",
        "affected": [{
            "package": {
                "name": "lodash",
                "ecosystem": "npm"
            },
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "4.17.21"}
                ]
            }]
        }],
        "severity": [{"type": "CVSS_V3", "score": "7.2"}]
    }"#;

    #[test]
    fn test_import_osv_json() {
        let conn = make_conn();
        let importer = OsvImporter::new(conn.clone());
        let count = importer.import_osv_json(SAMPLE_OSV_JSON, "npm").unwrap();
        assert_eq!(count, 1);

        let locked = conn.lock().unwrap();
        let name: String = locked
            .query_row(
                "SELECT package_name FROM known_vulnerabilities WHERE package_name = 'lodash'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "lodash");
    }

    #[test]
    fn test_import_osv_json_extracts_cve() {
        let conn = make_conn();
        let importer = OsvImporter::new(conn.clone());
        importer.import_osv_json(SAMPLE_OSV_JSON, "npm").unwrap();

        let locked = conn.lock().unwrap();
        let cve_id: Option<String> = locked
            .query_row(
                "SELECT cve_id FROM known_vulnerabilities WHERE package_name = 'lodash'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cve_id, Some("CVE-2021-23337".to_string()));
    }

    #[test]
    fn test_import_osv_json_extracts_version_range() {
        let conn = make_conn();
        let importer = OsvImporter::new(conn.clone());
        importer.import_osv_json(SAMPLE_OSV_JSON, "npm").unwrap();

        let locked = conn.lock().unwrap();
        let versions_json: String = locked.query_row(
            "SELECT vulnerable_versions FROM known_vulnerabilities WHERE package_name = 'lodash'",
            [],
            |row| row.get(0),
        ).unwrap();
        let versions: Vec<String> = serde_json::from_str(&versions_json).unwrap();
        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.contains("4.17.21")));
    }

    #[test]
    fn test_cvss_score_to_severity() {
        assert_eq!(cvss_score_to_severity(0.0), Severity::Info);
        assert_eq!(cvss_score_to_severity(2.5), Severity::Low);
        assert_eq!(cvss_score_to_severity(5.0), Severity::Medium);
        assert_eq!(cvss_score_to_severity(7.5), Severity::High);
        assert_eq!(cvss_score_to_severity(9.5), Severity::Critical);
    }

    #[test]
    fn test_osv_query_request_serialization() {
        let req = OsvQueryRequest {
            package: OsvQueryPackage {
                name: "lodash".to_string(),
                ecosystem: "npm".to_string(),
            },
            version: Some("4.17.20".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"name\":\"lodash\""));
        assert!(json.contains("\"ecosystem\":\"npm\""));
        assert!(json.contains("\"version\":\"4.17.20\""));
    }

    #[test]
    fn test_osv_query_response_parsing() {
        let json = r#"{
            "vulns": [{
                "id": "GHSA-test-1234",
                "aliases": ["CVE-2021-99999"],
                "summary": "Test vuln",
                "affected": [{
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
                }],
                "severity": [{"type": "CVSS_V3", "score": "8.0"}]
            }]
        }"#;
        let resp: OsvQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.vulns.len(), 1);
        assert_eq!(resp.vulns[0].id, "GHSA-test-1234");
    }

    #[test]
    fn test_osv_query_response_empty() {
        let json = r#"{}"#;
        let resp: OsvQueryResponse = serde_json::from_str(json).unwrap();
        assert!(resp.vulns.is_empty());
    }
}
