//! Cloud publish client module — authenticated upload to Sicario Cloud API.

pub mod client;

pub use client::{
    collect_git_metadata, resolve_cloud_url, PublishClient, PublishResponse, ScanMetadata,
    ScanReport,
};
