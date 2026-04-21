//! Performance benchmarking module — timing, memory, per-language breakdown.

pub mod runner;

pub use runner::{BenchmarkComparison, BenchmarkResult, BenchmarkRunner, LanguageBenchmark};
