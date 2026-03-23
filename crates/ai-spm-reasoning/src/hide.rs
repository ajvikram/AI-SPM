use ai_spm_core::error::{AiSpmError, Result};
use ai_spm_core::types::{TaintLabel, VariableRef};
use std::collections::HashMap;
use tracing::info;

/// Stored hidden data that hasn't been appended to the conversation context.
#[derive(Debug, Clone)]
pub struct HiddenData {
    pub variable_ref: VariableRef,
    pub content: String,
    pub source: String,
    pub taint_label: TaintLabel,
}

/// HIDE Function — Selective Hiding per the FIDES model.
/// Stores potentially malicious tool outputs in isolated variables
/// rather than appending them to the conversation history.
pub struct HiddenVariableStore {
    variables: HashMap<VariableRef, HiddenData>,
    max_variables: usize,
}

impl HiddenVariableStore {
    pub fn new(max_variables: usize) -> Self {
        Self {
            variables: HashMap::new(),
            max_variables,
        }
    }

    /// Hide a tool output: store it in a variable without appending to context.
    /// Returns a VariableRef that can be used to inspect the data later.
    pub fn hide(
        &mut self,
        content: String,
        source: String,
        taint_label: TaintLabel,
    ) -> Result<VariableRef> {
        if self.variables.len() >= self.max_variables {
            return Err(AiSpmError::TaintViolation(format!(
                "Maximum hidden variables ({}) exceeded",
                self.max_variables
            )));
        }

        let var_ref = VariableRef::new();

        let data = HiddenData {
            variable_ref: var_ref.clone(),
            content,
            source: source.clone(),
            taint_label,
        };

        self.variables.insert(var_ref.clone(), data);
        info!(var_ref = %var_ref.0, source = %source, "Data hidden in variable store");

        Ok(var_ref)
    }

    /// Get hidden data by reference (for inspection by the quarantined LLM).
    pub fn get(&self, var_ref: &VariableRef) -> Result<&HiddenData> {
        self.variables
            .get(var_ref)
            .ok_or_else(|| AiSpmError::HiddenVariableNotFound(var_ref.0.to_string()))
    }

    /// Remove hidden data after it has been safely processed.
    pub fn remove(&mut self, var_ref: &VariableRef) -> Result<HiddenData> {
        self.variables
            .remove(var_ref)
            .ok_or_else(|| AiSpmError::HiddenVariableNotFound(var_ref.0.to_string()))
    }

    /// Get the number of currently hidden variables.
    pub fn count(&self) -> usize {
        self.variables.len()
    }

    /// Clear all hidden variables.
    pub fn clear(&mut self) {
        self.variables.clear();
        info!("Hidden variable store cleared");
    }

    /// List all variable references.
    pub fn list_refs(&self) -> Vec<&VariableRef> {
        self.variables.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hide_and_retrieve() {
        let mut store = HiddenVariableStore::new(100);

        let var_ref = store
            .hide(
                "Email content with potential injection".into(),
                "email_tool".into(),
                TaintLabel::untrusted_public(),
            )
            .unwrap();

        let data = store.get(&var_ref).unwrap();
        assert_eq!(data.source, "email_tool");
        assert_eq!(data.taint_label.integrity, IntegrityLevel::Low);
    }

    #[test]
    fn test_max_variables_enforced() {
        let mut store = HiddenVariableStore::new(2);

        store
            .hide("data1".into(), "src1".into(), TaintLabel::untrusted_public())
            .unwrap();
        store
            .hide("data2".into(), "src2".into(), TaintLabel::untrusted_public())
            .unwrap();

        let result = store.hide("data3".into(), "src3".into(), TaintLabel::untrusted_public());
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_variable() {
        let mut store = HiddenVariableStore::new(100);

        let var_ref = store
            .hide("data".into(), "src".into(), TaintLabel::untrusted_public())
            .unwrap();

        assert_eq!(store.count(), 1);
        let removed = store.remove(&var_ref).unwrap();
        assert_eq!(removed.content, "data");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_get_nonexistent_variable() {
        let store = HiddenVariableStore::new(100);
        let result = store.get(&VariableRef::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_store() {
        let mut store = HiddenVariableStore::new(100);
        store
            .hide("d1".into(), "s1".into(), TaintLabel::untrusted_public())
            .unwrap();
        store
            .hide("d2".into(), "s2".into(), TaintLabel::untrusted_public())
            .unwrap();

        assert_eq!(store.count(), 2);
        store.clear();
        assert_eq!(store.count(), 0);
    }
}
