use auxon_sdk::{
    plugin_utils::serde::from_str,
    reflector_config::{envsub, EnvSubError},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use send::Sender;

mod convert;
mod send;

pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct CommonConfig {
    /// The barectf effective-configuration yaml file
    #[serde(deserialize_with = "from_str")]
    pub config: Option<PathBuf>,

    /// An event name to consider as the trace-start signal.
    /// Used to detect system restarts.
    #[serde(alias = "start_event")]
    pub start_event: Option<String>,
}

pub trait HasCommonConfig {
    fn common_config(&self) -> &CommonConfig;
}

impl CommonConfig {
    pub fn envsub_config_path(&self) -> Result<Option<PathBuf>, EnvSubError> {
        let maybe_str = self.config.as_ref().and_then(|p| p.as_os_str().to_str());

        if let Some(s) = maybe_str {
            envsub(s).map(|s| Some(PathBuf::from(s)))
        } else {
            Ok(self.config.clone())
        }
    }
}
