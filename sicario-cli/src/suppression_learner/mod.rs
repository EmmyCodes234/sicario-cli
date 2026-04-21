//! Suppression learner module — pattern recording and auto-suppression suggestions.

pub mod learner;

pub use learner::{
    LearnedSuppression, SuppressionLearner, SuppressionLearning, SuppressionSuggestion,
};
