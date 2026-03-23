pub mod config;
pub mod error;
pub mod types;

pub use config::AppConfig;
pub use error::AiSpmError;
pub use types::*;

/// Initialize the global tracing subscriber for structured logging.
/// Call this once at application startup.
pub fn init_tracing(log_level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .json()
        .init();
}
