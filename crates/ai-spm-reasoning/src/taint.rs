use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{ConfidentialityLabel, IntegrityLevel, TaintLabel};
use std::collections::HashMap;
use tracing::{info, warn};

/// Taint Tracking Engine per the FIDES information-flow control model.
/// Maintains taint state per agent session and enforces taint-based access control.
pub struct TaintTracker {
    /// Current taint label for the session context
    context_taint: TaintLabel,
    /// Taint labels for individual data items
    data_labels: HashMap<String, TaintLabel>,
}

impl TaintTracker {
    /// Create a new taint tracker with a clean (high integrity, public) context.
    pub fn new() -> Self {
        Self {
            context_taint: TaintLabel::trusted_public(),
            data_labels: HashMap::new(),
        }
    }

    /// Get the current context taint label.
    pub fn context_taint(&self) -> &TaintLabel {
        &self.context_taint
    }

    /// Label a piece of data with integrity and confidentiality tags.
    pub fn label_data(
        &mut self,
        data_id: &str,
        integrity: IntegrityLevel,
        confidentiality: ConfidentialityLabel,
    ) -> TaintLabel {
        let label = TaintLabel {
            integrity,
            confidentiality,
        };
        self.data_labels.insert(data_id.to_string(), label.clone());

        info!(
            data_id = %data_id,
            integrity = ?label.integrity,
            "Data labeled"
        );

        label
    }

    /// Propagate taint when data is used in the context.
    /// This merges the data's taint into the session context.
    pub fn propagate_taint(&mut self, data_id: &str) -> Result<TaintLabel> {
        let data_label = self
            .data_labels
            .get(data_id)
            .ok_or_else(|| {
                AiSpmError::TaintViolation(format!("No taint label for data '{}'", data_id))
            })?
            .clone();

        let new_context = self.context_taint.merge(&data_label);

        if self.context_taint.integrity == IntegrityLevel::High
            && new_context.integrity == IntegrityLevel::Low
        {
            warn!(
                data_id = %data_id,
                "Context tainted: integrity downgraded from High to Low"
            );
        }

        self.context_taint = new_context.clone();
        Ok(new_context)
    }

    /// Check if a high-integrity action is allowed given the current context taint.
    /// Blocks consequential actions when the context is tainted with low-integrity data.
    pub fn check_taint_violation(
        &self,
        action: &str,
        requires_high_integrity: bool,
    ) -> Result<()> {
        if requires_high_integrity && self.context_taint.integrity == IntegrityLevel::Low {
            return Err(AiSpmError::TaintViolation(format!(
                "Action '{}' requires high integrity but context is tainted (low integrity). \
                 Use the HIDE function to isolate untrusted data.",
                action
            )));
        }
        Ok(())
    }

    /// Check if a reader is authorized to access data in the current context.
    pub fn check_confidentiality(&self, reader: &str) -> Result<()> {
        if !self.context_taint.confidentiality.can_read(reader) {
            return Err(AiSpmError::TaintViolation(format!(
                "Reader '{}' is not authorized to access data in the current context",
                reader
            )));
        }
        Ok(())
    }

    /// Reset the context taint to clean (e.g., after completing a task boundary).
    pub fn reset_context(&mut self) {
        self.context_taint = TaintLabel::trusted_public();
        info!("Context taint reset to clean");
    }

    /// Get the taint label for a specific data item.
    pub fn get_data_label(&self, data_id: &str) -> Option<&TaintLabel> {
        self.data_labels.get(data_id)
    }
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker_is_clean() {
        let tracker = TaintTracker::new();
        assert_eq!(tracker.context_taint().integrity, IntegrityLevel::High);
    }

    #[test]
    fn test_label_and_propagate_trusted_data() {
        let mut tracker = TaintTracker::new();
        tracker.label_data("user_input", IntegrityLevel::High, ConfidentialityLabel::public());
        tracker.propagate_taint("user_input").unwrap();
        assert_eq!(tracker.context_taint().integrity, IntegrityLevel::High);
    }

    #[test]
    fn test_propagate_untrusted_data_taints_context() {
        let mut tracker = TaintTracker::new();
        tracker.label_data("web_data", IntegrityLevel::Low, ConfidentialityLabel::public());
        tracker.propagate_taint("web_data").unwrap();
        assert_eq!(tracker.context_taint().integrity, IntegrityLevel::Low);
    }

    #[test]
    fn test_taint_violation_blocks_high_integrity_action() {
        let mut tracker = TaintTracker::new();
        tracker.label_data("email", IntegrityLevel::Low, ConfidentialityLabel::public());
        tracker.propagate_taint("email").unwrap();

        let result = tracker.check_taint_violation("send_payment", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_taint_violation_allows_low_integrity_action() {
        let mut tracker = TaintTracker::new();
        tracker.label_data("email", IntegrityLevel::Low, ConfidentialityLabel::public());
        tracker.propagate_taint("email").unwrap();

        let result = tracker.check_taint_violation("log_event", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_confidentiality_check() {
        let mut tracker = TaintTracker::new();
        tracker.label_data(
            "patient_data",
            IntegrityLevel::High,
            ConfidentialityLabel::restricted(vec!["doctor".into()]),
        );
        tracker.propagate_taint("patient_data").unwrap();

        assert!(tracker.check_confidentiality("doctor").is_ok());
        assert!(tracker.check_confidentiality("admin").is_err());
    }

    #[test]
    fn test_reset_context() {
        let mut tracker = TaintTracker::new();
        tracker.label_data("dirty", IntegrityLevel::Low, ConfidentialityLabel::public());
        tracker.propagate_taint("dirty").unwrap();
        assert_eq!(tracker.context_taint().integrity, IntegrityLevel::Low);

        tracker.reset_context();
        assert_eq!(tracker.context_taint().integrity, IntegrityLevel::High);
    }
}
