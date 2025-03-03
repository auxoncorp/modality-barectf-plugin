use serde::{Deserialize, Serialize};

pub use send::Sender;

mod convert;
mod send;

pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct CommonConfig {
    /// An event name to consider as the trace-start signal.
    /// Used to detect system restarts.
    #[serde(alias = "start_event")]
    pub start_event: Option<String>,
}

pub trait HasCommonConfig {
    fn common_config(&self) -> &CommonConfig;
}
