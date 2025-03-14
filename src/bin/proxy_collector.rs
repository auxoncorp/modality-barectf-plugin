use anyhow::anyhow;
use auxon_sdk::{
    init_tracing,
    plugin_utils::ingest::Config,
    plugin_utils::serde::from_str,
    reflector_config::{envsub, EnvSubError},
};
use barectf_parser::{Config as BarectfConfig, Parser};
use clap::Parser as ClapParser;
use modality_barectf_plugin::{CommonConfig, HasCommonConfig, Sender, PLUGIN_VERSION};
use rtt_proxy::{
    ProbeConfig, ProxySessionConfig, ProxySessionStatus, RttConfig, Target, TargetConfig,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::Duration,
};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, trace};
use url::Url;

/// Collect barectf streams from an RTT proxy service
#[derive(Debug, clap::Parser)]
#[clap(version, about = "Collect barectf streams from an RTT proxy service", long_about = None)]
struct CollectorOpts {
    /// Specify a target attach timeout.
    /// When provided, the plugin will continually attempt to attach and search
    /// for a valid RTT control block anywhere in the target RAM.
    ///
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "attach-timeout")]
    attach_timeout: Option<String>,

    /// Use the provided RTT control block address instead of scanning the target memory for it.
    #[clap(
        long,
        value_parser=clap_num::maybe_hex::<u32>,
        name = "control-block-address",
    )]
    control_block_address: Option<u32>,

    /// Extract the location in memory of the RTT control block debug symbol from an ELF file.
    #[clap(long, name = "elf-file")]
    elf_file: Option<PathBuf>,

    /// Set a breakpoint on the address of the given symbol used to signal
    /// when to optionally configure the channel mode and start reading.
    ///
    /// Can be an absolute address or symbol name.
    #[arg(long, name = "breakpoint")]
    breakpoint: Option<String>,

    /// Set a breakpoint on the address of the given symbol
    /// to signal a stopping condition.
    ///
    /// Can be an absolute address (decimal or hex) or symbol name.
    #[arg(long, name = "stop-on-breakpoint")]
    stop_on_breakpoint: Option<String>,

    /// Assume thumb mode when resolving symbols from the ELF file
    /// for breakpoint addresses.
    #[arg(long, requires = "elf-file")]
    thumb: bool,

    /// This session will have exclusive access to the core's
    /// control functionality (i.e. hardware breakpoints, reset, etc).
    /// If another session (i.e. the application to be booted by the bootloader)
    /// is requested on this core, it will be suspended until this session
    /// signals completion.
    #[clap(
        long,
        name = "bootloader",
        conflicts_with = "bootloader-companion-application"
    )]
    bootloader: bool,

    /// This session will not drive any of the core's
    /// control functionality (i.e. hardware breakpoints, reset, etc)
    #[clap(
        long,
        name = "bootloader-companion-application",
        conflicts_with = "bootloader"
    )]
    bootloader_companion_application: bool,

    /// The RTT up (target to host) channel number to poll on (defaults to 2).
    #[clap(long, name = "up-channel")]
    up_channel: Option<u32>,

    /// Select a specific probe instead of opening the first available one.
    ///
    /// Use '--probe VID:PID' or '--probe VID:PID:Serial' if you have more than one probe with the same VID:PID.
    #[clap(long = "probe", name = "probe")]
    probe_selector: Option<String>,

    /// The target chip to attach to (e.g. S32K344).
    #[clap(long, name = "chip")]
    chip: Option<String>,

    /// Protocol used to connect to chip.
    /// Possible options: [swd, jtag].
    ///
    /// The default value is swd.
    #[clap(long, name = "protocol")]
    protocol: Option<String>,

    /// The protocol speed in kHz.
    ///
    /// The default value is 4000.
    #[clap(long, name = "speed")]
    speed: Option<u32>,

    /// The selected core to target.
    ///
    /// The default value is 0.
    #[clap(long, name = "core")]
    core: Option<u32>,

    /// Reset the target on startup.
    #[clap(long, name = "reset")]
    reset: bool,

    /// Attach to the chip under hard-reset.
    #[clap(long, name = "attach-under-reset")]
    attach_under_reset: bool,

    /// Size of the host-side RTT buffer used to store data read off the target.
    ///
    /// The default value is 1024.
    #[clap(long, name = "rtt-reader-buffer-size")]
    rtt_read_buffer_size: Option<u32>,

    /// The host-side RTT polling interval.
    /// Note that when the interface returns no data, we delay longer than this
    /// interval to prevent USB connection instability.
    ///
    /// The default value is 1ms.
    ///
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "rtt-poll-interval")]
    rtt_poll_interval: Option<String>,

    /// The host-side RTT idle polling interval.
    ///
    /// The default value is 100ms.
    ///
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "rtt-idle-poll-interval")]
    rtt_idle_poll_interval: Option<String>,

    /// Force exclusive access to the probe.
    /// Any existing sessions using this probe will be shut down.
    #[clap(long, name = "force-exclusive")]
    force_exclusive: bool,

    /// Automatically attempt to recover the debug probe connection
    /// when an error is encountered
    #[clap(long, name = "auto-recover")]
    auto_recover: bool,

    /// Automatically stop the RTT session if no data is received
    /// within specified timeout duration.
    ///
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "no-data-timeout")]
    no_data_timeout: Option<String>,

    /// Specify a connection timeout.
    /// Accepts durations like "10ms" or "1minute 2seconds 22ms".
    #[clap(long, name = "connect-timeout")]
    connect_timeout: Option<String>,

    /// The barectf effective-configuration yaml file
    config: Option<PathBuf>,

    /// The remote RTT proxy server URL or address:port to connect to.
    ///
    /// The default is `127.0.0.1:8888`.
    remote: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct CollectorConfig {
    #[serde(alias = "attach_timeout")]
    attach_timeout: Option<String>,
    #[serde(deserialize_with = "from_str", alias = "control_block_address")]
    control_block_address: Option<u32>,
    #[serde(deserialize_with = "from_str", alias = "up_channel")]
    up_channel: Option<u32>,
    #[serde(alias = "probe_selector")]
    probe_selector: Option<String>,
    chip: Option<String>,
    protocol: Option<String>,
    #[serde(deserialize_with = "from_str")]
    speed: Option<u32>,
    #[serde(deserialize_with = "from_str")]
    core: Option<u32>,
    #[serde(deserialize_with = "from_str")]
    reset: Option<bool>,
    #[serde(deserialize_with = "from_str", alias = "attach_under_reset")]
    attach_under_reset: Option<bool>,
    #[serde(deserialize_with = "from_str", alias = "elf_file")]
    elf_file: Option<PathBuf>,
    #[serde(deserialize_with = "from_str")]
    thumb: Option<bool>,
    breakpoint: Option<String>,
    #[serde(deserialize_with = "from_str", alias = "rtt_read_buffer_size")]
    rtt_read_buffer_size: Option<u32>,
    #[serde(alias = "rtt_poll_interval")]
    rtt_poll_interval: Option<String>,
    #[serde(alias = "rtt_idle_poll_interval")]
    rtt_idle_poll_interval: Option<String>,
    #[serde(deserialize_with = "from_str", alias = "force_exclusive")]
    force_exclusive: Option<bool>,
    #[serde(deserialize_with = "from_str", alias = "auto_recover")]
    auto_recover: Option<bool>,
    #[serde(alias = "stop_on_breakpoint")]
    stop_on_breakpoint: Option<String>,
    #[serde(alias = "no_data_stop_timeout")]
    no_data_stop_timeout: Option<String>,
    #[serde(deserialize_with = "from_str")]
    bootloader: Option<bool>,
    #[serde(
        deserialize_with = "from_str",
        alias = "bootloader_companion_application"
    )]
    bootloader_companion_application: Option<bool>,
    #[serde(alias = "connect_timeout")]
    connect_timeout: Option<String>,
    remote: Option<String>,
    #[serde(flatten)]
    common: CommonConfig,
}

impl CollectorConfig {
    pub fn envsub_elf_file(&self) -> Result<Option<PathBuf>, EnvSubError> {
        let maybe_str = self.elf_file.as_ref().and_then(|p| p.as_os_str().to_str());

        if let Some(s) = maybe_str {
            envsub(s).map(|s| Some(PathBuf::from(s)))
        } else {
            Ok(self.elf_file.clone())
        }
    }
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

    if config.plugin.remote.is_none() {
        config.plugin.remote.clone_from(&opts.remote);
    }
    if config.plugin.common.config.is_none() {
        config.plugin.common.config.clone_from(&opts.config);
    }
    if config.plugin.attach_timeout.is_none() {
        config
            .plugin
            .attach_timeout
            .clone_from(&opts.attach_timeout);
    }
    if config.plugin.control_block_address.is_none() {
        config
            .plugin
            .control_block_address
            .clone_from(&opts.control_block_address);
    }
    if config.plugin.up_channel.is_none() {
        config.plugin.up_channel.clone_from(&opts.up_channel);
    }
    if config.plugin.probe_selector.is_none() {
        config
            .plugin
            .probe_selector
            .clone_from(&opts.probe_selector);
    }
    if config.plugin.chip.is_none() {
        config.plugin.chip.clone_from(&opts.chip);
    }
    if config.plugin.protocol.is_none() {
        config.plugin.protocol.clone_from(&opts.protocol);
    }
    if config.plugin.speed.is_none() {
        config.plugin.speed.clone_from(&opts.speed);
    }
    if config.plugin.core.is_none() {
        config.plugin.core.clone_from(&opts.core);
    }
    if config.plugin.reset.is_none() {
        config.plugin.reset = Some(opts.reset);
    }
    if config.plugin.attach_under_reset.is_none() {
        config.plugin.attach_under_reset = Some(opts.attach_under_reset);
    }
    if config.plugin.elf_file.is_none() {
        config.plugin.elf_file.clone_from(&opts.elf_file);
    }
    if config.plugin.thumb.is_none() {
        config.plugin.thumb = Some(opts.thumb);
    }
    if config.plugin.breakpoint.is_none() {
        config.plugin.breakpoint.clone_from(&opts.breakpoint);
    }
    if config.plugin.rtt_read_buffer_size.is_none() {
        config
            .plugin
            .rtt_read_buffer_size
            .clone_from(&opts.rtt_read_buffer_size);
    }
    if config.plugin.rtt_poll_interval.is_none() {
        config
            .plugin
            .rtt_poll_interval
            .clone_from(&opts.rtt_poll_interval);
    }
    if config.plugin.rtt_idle_poll_interval.is_none() {
        config
            .plugin
            .rtt_idle_poll_interval
            .clone_from(&opts.rtt_idle_poll_interval);
    }
    if config.plugin.force_exclusive.is_none() {
        config.plugin.force_exclusive = Some(opts.force_exclusive);
    }
    if config.plugin.auto_recover.is_none() {
        config.plugin.auto_recover = Some(opts.auto_recover);
    }
    if config.plugin.stop_on_breakpoint.is_none() {
        config
            .plugin
            .stop_on_breakpoint
            .clone_from(&opts.stop_on_breakpoint);
    }
    if config.plugin.no_data_stop_timeout.is_none() {
        config
            .plugin
            .no_data_stop_timeout
            .clone_from(&opts.no_data_timeout);
    }
    if config.plugin.bootloader.is_none() {
        config.plugin.bootloader = Some(opts.bootloader);
    }
    if config.plugin.bootloader_companion_application.is_none() {
        config.plugin.bootloader_companion_application =
            Some(opts.bootloader_companion_application);
    }
    if config.plugin.connect_timeout.is_none() {
        config
            .plugin
            .connect_timeout
            .clone_from(&opts.connect_timeout);
    }

    let bctf_cfg_from_conf_file = match config.plugin.common.envsub_config_path() {
        Ok(maybe_cfg) => maybe_cfg,
        Err(e) => {
            error!(%e, "Failed to run envsub on effective-configuration yaml path from reflector configuration file");
            config.plugin.common.config.clone()
        }
    };

    let bctf_cfg_path = bctf_cfg_from_conf_file
        .as_ref()
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

    let remote_string = if let Some(remote) = config.plugin.remote.as_ref() {
        remote.clone()
    } else {
        "127.0.0.1:8888".to_string()
    };

    let connect_timeout = config
        .plugin
        .connect_timeout
        .as_ref()
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid connect-timeout. {}", e))?;

    let attach_timeout = config
        .plugin
        .attach_timeout
        .as_ref()
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid attach-timeout. {}", e))?;

    let rtt_poll_interval = config
        .plugin
        .rtt_poll_interval
        .as_ref()
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid rtt-poll-interval. {}", e))?;

    let rtt_idle_poll_interval = config
        .plugin
        .rtt_idle_poll_interval
        .as_ref()
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid rtt-idle-poll-interval. {}", e))?;

    let no_data_stop_timeout = config
        .plugin
        .no_data_stop_timeout
        .as_ref()
        .map(|to| humantime::Duration::from_str(to))
        .transpose()
        .map_err(|e| anyhow!("Invalid no-data-stop-timeout. {}", e))?;

    let maybe_elf_file = match config.plugin.envsub_elf_file() {
        Ok(maybe_cfg) => maybe_cfg,
        Err(e) => {
            error!(%e, "Failed to run envsub on ELF file path from reflector configuration file");
            config.plugin.elf_file.clone()
        }
    };

    let maybe_control_block_address =
        if let Some(user_provided_addr) = config.plugin.control_block_address {
            debug!(
                rtt_addr = user_provided_addr,
                "Using explicit RTT control block address"
            );
            Some(user_provided_addr as u64)
        } else if let Some(elf_file) = &maybe_elf_file {
            debug!(elf_file = %elf_file.display(), "Reading ELF file");
            let mut file = fs::File::open(elf_file).await?;
            if let Some(rtt_addr) = get_rtt_symbol(&mut file).await {
                debug!(rtt_addr = rtt_addr, "Found RTT symbol");
                Some(rtt_addr)
            } else {
                debug!("Could not find RTT symbol in ELF file");
                None
            }
        } else {
            None
        };

    let maybe_setup_on_breakpoint_address = if let Some(bp_sym_or_addr) = &config.plugin.breakpoint
    {
        if let Some(bp_addr) = bp_sym_or_addr.parse::<u64>().ok().or(u64::from_str_radix(
            bp_sym_or_addr.trim_start_matches("0x"),
            16,
        )
        .ok())
        {
            Some(bp_addr)
        } else {
            let elf_file = maybe_elf_file
                .as_ref()
                .ok_or_else(|| "Using a breakpoint symbol name requires an ELF file".to_owned())?;
            let mut file = fs::File::open(elf_file).await?;
            let bp_addr = get_symbol(&mut file, bp_sym_or_addr).await.ok_or_else(|| {
                format!(
                    "Could not locate the address of symbol '{0}' in the ELF file",
                    bp_sym_or_addr
                )
            })?;
            if config.plugin.thumb.unwrap_or(false) {
                Some(bp_addr & !1)
            } else {
                Some(bp_addr)
            }
        }
    } else {
        None
    };

    let maybe_stop_on_breakpoint_address =
        if let Some(bp_sym_or_addr) = &config.plugin.stop_on_breakpoint {
            if let Some(bp_addr) = bp_sym_or_addr.parse::<u64>().ok().or(u64::from_str_radix(
                bp_sym_or_addr.trim_start_matches("0x"),
                16,
            )
            .ok())
            {
                Some(bp_addr)
            } else {
                let elf_file = maybe_elf_file.as_ref().ok_or_else(|| {
                    "Using a breakpoint symbol name requires an ELF file".to_owned()
                })?;
                let mut file = fs::File::open(elf_file).await?;
                let bp_addr = get_symbol(&mut file, bp_sym_or_addr).await.ok_or_else(|| {
                    format!(
                        "Could not locate the address of symbol '{0}' in the ELF file",
                        bp_sym_or_addr
                    )
                })?;
                if config.plugin.thumb.unwrap_or(false) {
                    Some(bp_addr & !1)
                } else {
                    Some(bp_addr)
                }
            }
        } else {
            None
        };

    let proxy_cfg = ProxySessionConfig {
        version: rtt_proxy::V1,
        probe: ProbeConfig {
            probe_selector: config.plugin.probe_selector.clone(),
            protocol: config.plugin.protocol.clone().unwrap_or("SWD".to_owned()),
            speed_khz: config.plugin.speed.unwrap_or(4000),
            target: config
                .plugin
                .chip
                .as_ref()
                .map(|t| Target::Specific(t.clone()))
                .unwrap_or(Target::Auto),
            attach_under_reset: config.plugin.attach_under_reset.unwrap_or(false),
            force_exclusive: config.plugin.force_exclusive.unwrap_or(false),
        },
        target: TargetConfig {
            auto_recover: config.plugin.auto_recover.unwrap_or(false),
            core: config.plugin.core.unwrap_or(0),
            reset: config.plugin.reset.unwrap_or(false),
            bootloader: config.plugin.bootloader.unwrap_or(false),
            bootloader_companion_application: config
                .plugin
                .bootloader_companion_application
                .unwrap_or(false),
        },
        rtt: RttConfig {
            attach_timeout_ms: attach_timeout.map(|t| t.as_millis() as _),
            setup_on_breakpoint_address: maybe_setup_on_breakpoint_address,
            stop_on_breakpoint_address: maybe_stop_on_breakpoint_address,
            no_data_stop_timeout_ms: no_data_stop_timeout.map(|t| t.as_millis() as _),
            control_block_address: maybe_control_block_address,
            up_channel: config.plugin.up_channel.unwrap_or(2),
            down_channel: 2, // Not used when disable_control_plane is set
            disable_control_plane: true,
            restart: false,
            rtt_read_buffer_size: config.plugin.rtt_read_buffer_size.unwrap_or(1024),
            rtt_poll_interval_ms: rtt_poll_interval.map(|t| t.as_millis() as _).unwrap_or(1),
            rtt_idle_poll_interval_ms: rtt_idle_poll_interval
                .map(|t| t.as_millis() as _)
                .unwrap_or(100),
        },
    };
    trace!(?proxy_cfg);

    // TODO ------ ^^^^ here

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

    let tcp_stream = match attach_timeout {
        Some(to) if !to.is_zero() => {
            start_session_retry_loop(
                &remote,
                to.into(),
                connect_timeout.map(|t| t.into()),
                &proxy_cfg,
            )
            .await?
        }
        _ => start_session(&remote, connect_timeout.map(|t| t.into()), &proxy_cfg).await?,
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

async fn start_session_retry_loop(
    remote: &SocketAddr,
    attach_timeout: Duration,
    connect_timeout: Option<Duration>,
    cfg: &ProxySessionConfig,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(Ok(s)) =
        tokio::time::timeout(attach_timeout, start_session(remote, connect_timeout, cfg)).await
    {
        Ok(s)
    } else {
        start_session(remote, connect_timeout, cfg).await
    }
}

async fn start_session(
    remote: &SocketAddr,
    connect_timeout: Option<Duration>,
    cfg: &ProxySessionConfig,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut sock = match connect_timeout {
        Some(to) if !to.is_zero() => connect_retry_loop(remote, to).await?,
        _ => {
            debug!(remote = %remote, "Connecting to to remote");
            TcpStream::connect(remote).await?
        }
    };

    sock.set_nodelay(true)?;

    // Send session config
    debug!("Starting a new session");
    let mut data = Vec::new();
    let mut se = serde_json::Serializer::new(&mut data);
    cfg.serialize(&mut se)?;
    sock.write_all(&data).await?;

    // Read response
    // TODO switch over to tokio-serde, fortunately this is a pretty small type
    data.clear();
    let status = loop {
        let byte = sock.read_u8().await?;
        data.push(byte);
        let mut de = serde_json::Deserializer::from_reader(&data[..]);
        match ProxySessionStatus::deserialize(&mut de) {
            Ok(status) => break status,
            Err(_) => continue,
        }
    };

    match status {
        rtt_proxy::ProxySessionStatus::Started(id) => {
            debug!(%id, "Session started");
            Ok(sock)
        }
        rtt_proxy::ProxySessionStatus::Error(e) => Err(e.into()),
    }
}

async fn connect_retry_loop(
    remote: &SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    info!(remote = %remote, timeout = ?timeout, "Connecting to to remote");
    if let Ok(Ok(s)) = tokio::time::timeout(timeout, TcpStream::connect(remote)).await {
        Ok(s)
    } else {
        Ok(TcpStream::connect(remote).await?)
    }
}

async fn get_rtt_symbol<T: io::AsyncRead + io::AsyncSeek + std::marker::Unpin>(
    file: &mut T,
) -> Option<u64> {
    get_symbol(file, "_SEGGER_RTT").await
}

async fn get_symbol<T: io::AsyncRead + io::AsyncSeek + std::marker::Unpin>(
    file: &mut T,
    symbol: &str,
) -> Option<u64> {
    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).await.is_ok() {
        if let Ok(binary) = goblin::elf::Elf::parse(buffer.as_slice()) {
            for sym in &binary.syms {
                if let Some(name) = binary.strtab.get_at(sym.st_name) {
                    if name == symbol {
                        return Some(sym.st_value);
                    }
                }
            }
        }
    }
    None
}
