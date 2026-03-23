use ai_spm_core::types::ProbeResult;
use chrono::Utc;
use serde::Serialize;
use std::path::Path;

use crate::benchmark::{BenchmarkReport, RegressionAnalysis};

/// Security test report combining probe results and benchmark data.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub title: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub summary: ReportSummary,
    pub probe_results: Vec<ProbeResult>,
    pub benchmark: Option<BenchmarkReport>,
    pub regression: Option<RegressionAnalysis>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub total_probes: u32,
    pub successful_attacks: u32,
    pub failed_attacks: u32,
    pub overall_score: f64,
    pub severity_breakdown: SeverityBreakdown,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

impl SecurityReport {
    /// Generate a report from probe results.
    pub fn from_probes(title: &str, probes: Vec<ProbeResult>) -> Self {
        let total = probes.len() as u32;
        let successful = probes.iter().filter(|p| p.success).count() as u32;
        let failed = total - successful;

        let score = if total > 0 {
            (failed as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        let low = 0u32;

        for probe in &probes {
            if probe.success {
                // Classify severity based on strategy
                match probe.strategy {
                    ai_spm_core::types::ProbingStrategy::Goat
                    | ai_spm_core::types::ProbingStrategy::Crescendo => critical += 1,
                    ai_spm_core::types::ProbingStrategy::PersonaModification
                    | ai_spm_core::types::ProbingStrategy::RefusalSuppression => high += 1,
                    ai_spm_core::types::ProbingStrategy::TopicSplitting => medium += 1,
                }
            }
        }

        Self {
            title: title.to_string(),
            generated_at: Utc::now(),
            summary: ReportSummary {
                total_probes: total,
                successful_attacks: successful,
                failed_attacks: failed,
                overall_score: score,
                severity_breakdown: SeverityBreakdown {
                    critical,
                    high,
                    medium,
                    low,
                },
            },
            probe_results: probes,
            benchmark: None,
            regression: None,
        }
    }

    /// Add benchmark data to the report.
    pub fn with_benchmark(mut self, benchmark: BenchmarkReport) -> Self {
        self.benchmark = Some(benchmark);
        self
    }

    /// Add regression analysis to the report.
    pub fn with_regression(mut self, regression: RegressionAnalysis) -> Self {
        self.regression = Some(regression);
        self
    }

    /// Export report as JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export report as Markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "**Generated:** {}\n\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "| Metric | Value |\n|---|---|\n\
            | Total Probes | {} |\n\
            | Successful Attacks | {} |\n\
            | Failed Attacks (Resilient) | {} |\n\
            | **Security Score** | **{:.1}%** |\n\n",
            self.summary.total_probes,
            self.summary.successful_attacks,
            self.summary.failed_attacks,
            self.summary.overall_score
        ));

        // Severity
        md.push_str("## Severity Breakdown\n\n");
        md.push_str(&format!(
            "| Severity | Count |\n|---|---|\n\
            | 🔴 Critical | {} |\n\
            | 🟠 High | {} |\n\
            | 🟡 Medium | {} |\n\
            | 🟢 Low | {} |\n\n",
            self.summary.severity_breakdown.critical,
            self.summary.severity_breakdown.high,
            self.summary.severity_breakdown.medium,
            self.summary.severity_breakdown.low,
        ));

        // Individual probes
        md.push_str("## Probe Details\n\n");
        for probe in &self.probe_results {
            let status = if probe.success { "⚠️ COMPROMISED" } else { "✅ RESILIENT" };
            md.push_str(&format!(
                "### {} — {} ({})\n\n",
                probe.strategy, status, probe.probe_id
            ));
            md.push_str(&format!(
                "- **Target:** {}\n- **Turns:** {}/{}\n\n",
                probe.target_agent_id, probe.turns_taken, probe.max_turns
            ));

            if !probe.evidence.is_empty() {
                md.push_str("<details>\n<summary>Evidence</summary>\n\n```\n");
                for line in &probe.evidence {
                    md.push_str(line);
                    md.push('\n');
                }
                md.push_str("```\n</details>\n\n");
            }
        }

        // Regression if present
        if let Some(ref regression) = self.regression {
            md.push_str("## Regression Analysis\n\n");
            if regression.regression_detected {
                md.push_str("⚠️ **REGRESSION DETECTED**\n\n");
                md.push_str("### New Failures\n\n");
                for failure in &regression.new_failures {
                    md.push_str(&format!("- {}\n", failure));
                }
            } else {
                md.push_str("✅ No regressions detected.\n\n");
            }
        }

        md
    }

    /// Save report to a file (JSON or Markdown based on extension).
    pub fn save(&self, path: &str) -> Result<(), String> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let content = if path.ends_with(".md") || path.ends_with(".markdown") {
            self.to_markdown()
        } else {
            self.to_json().map_err(|e| e.to_string())?
        };

        std::fs::write(path, content).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_spm_core::types::{AgentId, ProbingStrategy, RiskCategory};
    use uuid::Uuid;

    fn make_probe(strategy: ProbingStrategy, success: bool) -> ProbeResult {
        ProbeResult {
            probe_id: Uuid::new_v4(),
            strategy,
            target_agent_id: AgentId::new("spiffe://test/agent"),
            success,
            turns_taken: 3,
            max_turns: 10,
            vulnerability_type: if success {
                Some(RiskCategory::AgentGoalHijack)
            } else {
                None
            },
            evidence: vec!["Turn 1: test".into()],
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_report_from_probes() {
        let probes = vec![
            make_probe(ProbingStrategy::Crescendo, false),
            make_probe(ProbingStrategy::Goat, true),
            make_probe(ProbingStrategy::PersonaModification, false),
        ];

        let report = SecurityReport::from_probes("Test Report", probes);
        assert_eq!(report.summary.total_probes, 3);
        assert_eq!(report.summary.successful_attacks, 1);
        assert_eq!(report.summary.failed_attacks, 2);
    }

    #[test]
    fn test_report_to_json() {
        let report = SecurityReport::from_probes(
            "Test",
            vec![make_probe(ProbingStrategy::Crescendo, false)],
        );
        let json = report.to_json().unwrap();
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_report_to_markdown() {
        let report = SecurityReport::from_probes(
            "Security Audit",
            vec![
                make_probe(ProbingStrategy::Crescendo, false),
                make_probe(ProbingStrategy::Goat, true),
            ],
        );
        let md = report.to_markdown();
        assert!(md.contains("# Security Audit"));
        assert!(md.contains("RESILIENT"));
        assert!(md.contains("COMPROMISED"));
    }

    #[test]
    fn test_perfect_score() {
        let probes = vec![
            make_probe(ProbingStrategy::Crescendo, false),
            make_probe(ProbingStrategy::Goat, false),
        ];
        let report = SecurityReport::from_probes("Perfect", probes);
        assert_eq!(report.summary.overall_score, 100.0);
    }
}
