# modality-barectf-plugin

A Modality Reflector plugin suite for barectf-generated CTF trace data

## Configuration
Lowercase names are the config keys which may be used in a reflector
config toml file. Uppercase names are environment variables which may
be used for the same configuration.

### Common
These options are used by both the collectors and the importers.

* `config`/ `MODALITY_BARECTF_CONFIG`
The barectf effective-configuration yaml file.

* `start-event` / `MODALITY_BARECTF_START_EVENT`
An event name to consider as the trace-start signal.
Used to detect system restarts.

* `MODALITY_RUN_ID`
The run id to value to use in timeline metadata (`timeline.run_id`). This is used as the basis for the segmentation method used in the default Modality workspace.
Defaults to a randomly generated uuid.

* `MODALITY_AUTH_TOKEN`
The content of the auth token to use when connecting to Modality. If this is not set, the auth token used by the Modality CLI is read from `~/.config/modality_cli/.user_auth_token`

* `MODALITY_HOST`
The hostname where the modality server is running.

### TCP Collector
These options are used by the TCP collector.

* `connect-timeout` / `MODALITY_BARECTF_CONNECT_TIMEOUT`
Specify a connection timeout.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `remote` / `MODALITY_BARECTF_REMOTE`
The remote TCP server URL or address:port to connect to.
The default is `127.0.0.1:8888`.

### RTT Proxy Collector
These options are used by the [RTT Proxy](https://github.com/auxoncorp/trace-recorder-rtt-proxy) collector.

* `attach-timeout` / `MODALITY_BARECTF_CONNECT_TIMEOUT`
Specify a target attach timeout.
When provided, the plugin will continually attempt to attach and search for a valid RTT control block anywhere in the target RAM.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `control-block-address` / `MODALITY_BARECTF_CONTROL_BLOCK_ADDRESS`
Use the provided RTT control block address instead of scanning the target memory for it.

* `elf-file` / `MODALITY_BARECTF_ELF_FILE`
Extract the location in memory of the RTT control block debug symbol from an ELF file.

* `thumb` / `MODALITY_BARECTF_THUMB`
Assume thumb mode when resolving symbols from the ELF file for breakpoint addresses.

* `breakpoint` / `MODALITY_BARECTF_BREAKPOINT`
Set a breakpoint on the address of the given symbol used to signal when to optionally configure the channel mode and start reading.
Can be an absolute address or symbol name.

* `stop-on-breakpoint` / `MODALITY_BARECTF_STOP_ON_BREAKPOINT`
Set a breakpoint on the address of the given symbol to signal a stopping condition.
Can be an absolute address (decimal or hex) or symbol name.

* `bootloader` / `MODALITY_BARECTF_BOOTLOADER`
This session will have exclusive access to the core's control functionality (i.e. hardware breakpoints, reset, etc).
If another session (i.e. the application to be booted by the bootloader) is requested on this core,
it will be suspended until this session signals completion.

* `bootloader-companion-application` / `MODALITY_BARECTF_BOOTLOADER_COMPANION_APPLICATION`
This session will not drive any of the core's control functionality (i.e. hardware breakpoints, reset, etc).

* `up-channel` / `MODALITY_BARECTF_UP_CHANNEL`
The RTT up (target to host) channel number to poll on (defaults to 2).

* `probe` / `MODALITY_BARECTF_PROBE`
Select a specific probe instead of opening the first available one.
Use '--probe VID:PID' or '--probe VID:PID:Serial' if you have more than one probe with the same VID:PID.

* `chip` / `MODALITY_BARECTF_CHIP`
The target chip to attach to (e.g. S32K344).

* `protocol` / `MODALITY_BARECTF_PROTOCOL`
Protocol used to connect to chip. Possible options: [swd, jtag].
The default value is swd.

* `speed` / `MODALITY_BARECTF_SPEED`
The protocol speed in kHz.
The default value is 4000.

* `core` / `MODALITY_BARECTF_CORE`
The selected core to target.
The default value is 0.

* `reset` / `MODALITY_BARECTF_RESET`
Reset the target on startup.

* `attach-under-reset` / `MODALITY_BARECTF_ATTACH_UNDER_RESET`
Attach to the chip under hard-reset.

* `rtt-read-buffer-size` / `MODALITY_BARECTF_RTT_READ_BUFFER_SIZE`
Size of the host-side RTT buffer used to store data read off the target.
The default value is 1024.

* `rtt-poll-interval` / `MODALITY_BARECTF_RTT_POLL_INTERVAL`
The host-side RTT polling interval. Note that when the interface returns no data,
we delay longer than this interval to prevent USB connection instability.
The default value is 1ms.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `rtt-idle-poll-interval` / `MODALITY_BARECTF_RTT_IDLE_POLL_INTERVAL`
The host-side RTT idle polling interval.
The default value is 100ms.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `force-exclusive` / `MODALITY_BARECTF_FORCE_EXCLUSIVE`
Force exclusive access to the probe. Any existing sessions using this probe will be shut down.

* `auto-recover` / `MODALITY_BARECTF_AUTO_RECOVER`
Automatically attempt to recover the debug probe connection when an error is encountered.

* `no-data-timeout` / `MODALITY_BARECTF_NO_DATA_TIMEOUT`
Automatically stop the RTT session if no data is received within specified timeout duration.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `connect-timeout` / `MODALITY_BARECTF_CONNECT_TIMEOUT`
Specify a connection timeout.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `remote` / `MODALITY_BARECTF_REMOTE`
The remote RTT proxy server URL or address:port to connect to.
The default is `127.0.0.1:8888`.

### Importer
These options are used by the importer.

* `file` / `MODALITY_BARECTF_FILE`
The binary CTF stream(s) file.

## Adapter Concept Mapping
The following describes the default mapping between barectf concepts and Modality's concepts.

* Timelines are created for each CTF stream class
* Event names are the CTF event class names
* Event structure fields are provided as event attributes
* Array field types are truncated to a maximum of 10 elements

### Event Counter and Timestamps

Raw event count and timestamp timer ticks are provided alongside the rollover-tracked values.
If the default CTF stream clock contains the frequency, we additionally convert timestamp ticks to nanoseconds.

* Raw timestamp clock cycles are available on the `event.internal.barectf.clock.cycles` attribute
* Rollover tracking timestamp cycles are available on the `event.internal.barectf.timestamp.cycles` attribute
* Raw event count is available on the `event.internal.barectf.event.count` attribute
* When discarded events are present in `event.packet_context.events_discarded`, a warning message is logged.
