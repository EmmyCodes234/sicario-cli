//! Post-fix verification module — re-scan after fix application.
//!
//! Provides `VerificationScanner` which re-scans a patched file to confirm
//! the targeted vulnerability is resolved and no new findings were introduced.
//!
//! Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6

pub mod scanner;

pub use scanner::{
    OriginalFinding, VerificationResult, VerificationScanner, VerificationScanning,
};
