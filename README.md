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

* `connect-timeout` / `MODALITY_BARECTF_START_EVENT`
Specify a connection timeout.
Accepts durations like "10ms" or "1minute 2seconds 22ms".

* `remote` / `MODALITY_BARECTF_REMOTE`
The remote TCP server URL or address:port to connect to.
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
