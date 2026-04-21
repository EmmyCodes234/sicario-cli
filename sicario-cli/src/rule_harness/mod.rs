//! Rule quality enforcement module — TP/TN test execution and quality reports.

pub mod harness;

pub use harness::{
    AggregateQualityReport, RuleQualityReport, RuleQualityValidation, RuleTestHarness,
    RuleValidationReport,
};
