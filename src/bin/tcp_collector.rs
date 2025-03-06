use anyhow::anyhow;
use auxon_sdk::plugin_utils::serde::from_str;
use auxon_sdk::{init_tracing, plugin_utils::ingest::Config};
use barectf_parser::{Config as BarectfConfig, Parser};
use clap::Parser as ClapParser;
use modality_barectf_plugin::{CommonConfig, HasCommonConfig, Sender, PLUGIN_VERSION};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::{
    fs,
    io::BufReader,
    net::TcpStream,
    time::{Duration, Instant},
};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info};
use url::Url;

/// Collect barectf streams from a TCP connection
#[derive(Debug, clap::Parser)]
#[clap(version, about = "Collect barectf streams from a TCP connection", long_about = None)]
struct CollectorOpts {
    /// Specify a connection timeout.
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "connect-timeout")]
    connect_timeout: Option<String>,

    /// The barectf effective-configuration yaml file
    config: Option<PathBuf>,

    /// The remote TCP server URL or address:port to connect to.
    ///
    /// The default is `127.0.0.1:8888`.
    remote: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct CollectorConfig {
    /// Specify a connection timeout.
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[serde(deserialize_with = "from_str", alias = "connect_timeout")]
    connect_timeout: Option<String>,

    /// The remote TCP server URL or address:port to connect to.
    ///
    /// The default is `127.0.0.1:8888`.
    #[serde(deserialize_with = "from_str")]
    remote: Option<String>,

    #[serde(flatten)]
    common: CommonConfig,
}

impl HasCommonConfig for CollectorConfig {
    fn common_config(&self) -> &CommonConfig {
        &self.common
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing!();

    let opts = CollectorOpts::parse();

    let mut config = Config::<CollectorConfig>::load("MODALITY_BARECTF_")?;

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

    let remote_string = if let Some(remote) = opts.remote.as_ref().or(config.plugin.remote.as_ref())
    {
        remote.clone()
    } else {
        "127.0.0.1:8888".to_string()
    };

    let common_timeline_attrs = vec![
        (
            "modality_barectf.plugin.version".into(),
            PLUGIN_VERSION.into(),
        ),
        (
            "modality_barectf.tcp_collector.remote".into(),
            remote_string.clone().into(),
        ),
    ];

    let connect_timeout = opts
        .connect_timeout
        .as_ref()
        .or(config.plugin.connect_timeout.as_ref())
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid connect-timeout. {}", e))?;

    let client = config
        .connect_and_authenticate_ingest()
        .await
        .map_err(|e| anyhow!("Failed to connect to modality/reflector. {}", e))?;

    info!("Connected to Modality backend");

    let mut sender = Sender::new(
        client,
        &bctf_cfg,
        common_timeline_attrs.into_iter().collect(),
        config,
    );

    let remote = if let Ok(socket_addr) = remote_string.parse::<SocketAddr>() {
        socket_addr
    } else {
        let url = Url::parse(&remote_string)
            .map_err(|e| anyhow!("Failed to parse remote '{}' as URL. {}", remote_string, e))?;
        debug!(remote_url = %url);
        let socket_addrs = url
            .socket_addrs(|| None)
            .map_err(|e| anyhow!("Failed to resolve remote URL '{}'. {}", url, e))?;
        *socket_addrs
            .first()
            .ok_or_else(|| anyhow!("Could not resolve URL '{}'", url))?
    };

    let tcp_stream = match connect_timeout {
        Some(to) if !to.is_zero() => connect_retry_loop(&remote, to.into()).await?,
        _ => {
            info!(remote = %remote, "Connecting to to remote");
            TcpStream::connect(remote).await?
        }
    };

    let mut join_handle = tokio::spawn(async move {
        let decoder = Parser::new(&bctf_cfg)?.into_packet_decoder();
        let mut reader = FramedRead::new(BufReader::new(tcp_stream), decoder);

        while let Some(pkt_res) = reader.next().await {
            let pkt = match pkt_res {
                Ok(p) => p,
                Err(e) => {
                    // NOTE: doesn't support recovery yet
                    sender.close().await?;
                    return Err(anyhow!("Failed to parse CTF packet from stream. {}", e));
                }
            };

            sender.handle_packet(&pkt).await?;
        }

        sender.close().await?;
        info!("Finished");

        Ok(())
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            debug!("User signaled shutdown");
            join_handle.abort();
        }
        res = &mut join_handle => {
            match res? {
                Ok(_) => {},
                Err(e) => return Err(e.into()),
            }
        }
    };

    Ok(())
}

async fn connect_retry_loop(
    remote: &SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    info!(remote = %remote, timeout = ?timeout, "Connecting to to remote");
    let inner_timeout = timeout / 4;
    let start = Instant::now();
    while Instant::now().duration_since(start) <= timeout {
        match tokio::time::timeout(inner_timeout, TcpStream::connect(remote)).await {
            Ok(s) => match s {
                Ok(s) => return Ok(s),
                Err(_) => {
                    continue;
                }
            },
            Err(_e) => {
                continue;
            }
        }
    }
    Ok(TcpStream::connect(remote).await?)
}
