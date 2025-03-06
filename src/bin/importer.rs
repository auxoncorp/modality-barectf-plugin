use anyhow::anyhow;
use auxon_sdk::plugin_utils::serde::from_str;
use auxon_sdk::{init_tracing, plugin_utils::ingest::Config};
use barectf_parser::{Config as BarectfConfig, Parser};
use clap::Parser as ClapParser;
use modality_barectf_plugin::{CommonConfig, HasCommonConfig, Sender, PLUGIN_VERSION};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::{fs, io::BufReader};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{error, info};

/// Import barectf stream files
#[derive(Debug, clap::Parser)]
#[clap(version, about = "Import barectf stream files", long_about = None)]
struct ImporterOpts {
    /// The barectf effective-configuration yaml file
    config: Option<PathBuf>,

    /// The binary CTF stream file(s)
    ///
    /// Can be supplied multiple times
    file: Vec<PathBuf>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct ImporterConfig {
    /// The binary CTF stream(s) file
    #[serde(deserialize_with = "from_str")]
    file: Option<PathBuf>,

    #[serde(flatten)]
    common: CommonConfig,
}

impl HasCommonConfig for ImporterConfig {
    fn common_config(&self) -> &CommonConfig {
        &self.common
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing!();

    let opts = ImporterOpts::parse();

    let mut config = Config::<ImporterConfig>::load("MODALITY_BARECTF_")?;

    // Time domain is handled expclicitly by the plugin
    config.time_domain = None;

    let bctf_cfg_from_conf_file = match config.plugin.common.envsub_config_path() {
        Ok(maybe_cfg) => maybe_cfg,
        Err(e) => {
            error!(%e, "Failed to run envsub on effective-configuration yaml path from reflector configuration file");
            config.plugin.common.config.clone()
        }
    };

    let bctf_cfg_path = opts
        .config
        .as_ref()
        .or(bctf_cfg_from_conf_file.as_ref())
        .ok_or_else(|| anyhow!("Missing barectf effective-configuration yaml file"))?;
    info!(file = %bctf_cfg_path.display(), "Reading effective-configuration yaml");
    let bctf_cfg_content = fs::read_to_string(&bctf_cfg_path).await.map_err(|e| {
        anyhow!(
            "Failed to open barectf effective-configuration yaml file '{}'. {}",
            bctf_cfg_path.display(),
            e
        )
    })?;
    let bctf_cfg: BarectfConfig = serde_yaml::from_str(&bctf_cfg_content).map_err(|e| {
        anyhow!(
            "Failed to parse barectf effective-configuration yaml file '{}'. {}",
            bctf_cfg_path.display(),
            e
        )
    })?;

    let stream_paths: Vec<PathBuf> = opts
        .file
        .iter()
        .chain(config.plugin.file.iter())
        .cloned()
        .collect();
    if stream_paths.is_empty() {
        return Err(anyhow!("Missing CTF stream file(s). Specify a path to import on the command line or configuration file").into());
    }

    let common_timeline_attrs = vec![
        (
            "modality_barectf.plugin.version".into(),
            PLUGIN_VERSION.into(),
        ),
        (
            "modality_barectf.importer.config.file_name".into(),
            bctf_cfg_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "NA".to_owned())
                .into(),
        ),
    ];

    let client = config.connect_and_authenticate_ingest().await?;
    info!("Connected to Modality backend");

    let mut sender = Sender::new(
        client,
        &bctf_cfg,
        common_timeline_attrs.into_iter().collect(),
        config,
    );

    // Import each stream file
    for stream_path in stream_paths.into_iter() {
        info!(file = %stream_path.display(), "Importing CTF stream");

        let stream = fs::File::open(&stream_path).await.map_err(|e| {
            anyhow!(
                "Failed to open stream file '{}'. {}",
                stream_path.display(),
                e
            )
        })?;

        let decoder = Parser::new(&bctf_cfg)?.into_packet_decoder();
        let mut reader = FramedRead::new(BufReader::new(stream), decoder);

        while let Some(pkt_res) = reader.next().await {
            let pkt = match pkt_res {
                Ok(p) => p,
                Err(e) => {
                    // NOTE: doesn't support recovery yet
                    sender.close().await?;
                    return Err(anyhow!("Failed to parse CTF packet from stream. {}", e).into());
                }
            };

            sender.handle_packet(&pkt).await?;
        }
    }

    sender.close().await?;
    info!("Finished importing");

    Ok(())
}
