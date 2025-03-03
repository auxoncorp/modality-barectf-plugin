use crate::{
    convert::{ClockExt, EventExt, TimelineExt},
    HasCommonConfig,
};
use auxon_sdk::{
    api::{AttrKey, AttrVal, TimelineId, Uuid},
    plugin_utils::ingest::Config,
};
use barectf_parser::{
    Config as BarectfConfig, Packet, StreamId, TrackingInstant, UnsignedIntegerFieldType,
};
use fxhash::FxHashMap;
use internment::Intern;
use std::collections::{hash_map::Entry, HashMap};
use tracing::{debug, warn};

pub struct Sender<C: HasCommonConfig> {
    client: auxon_sdk::plugin_utils::ingest::Client,
    common_timeline_attrs: Vec<(AttrKey, AttrVal)>,
    _config: Config<C>,
    known_timelines: HashMap<StreamId, TimelineId>,
    current_timeline: Option<TimelineId>,
    start_event: Option<Intern<String>>,
    clock_uuids: FxHashMap<StreamName, Uuid>,
    timestamp_field_types: FxHashMap<StreamName, UnsignedIntegerFieldType>,
    streams_state: FxHashMap<StreamId, StreamState>,
}

type StreamName = Intern<String>;

struct StreamState {
    timestamp_tracker: Option<TrackingInstant>,
    clock_attrs: Vec<(AttrKey, AttrVal)>,
    event_count: u64,
    packet_seqnum: Option<u64>,
    event_ordering: u128,
}

impl<C: HasCommonConfig> Sender<C> {
    pub fn new(
        client: auxon_sdk::plugin_utils::ingest::Client,
        bctf_config: &BarectfConfig,
        mut common_timeline_attrs: HashMap<AttrKey, AttrVal>,
        config: Config<C>,
    ) -> Self {
        let mut clock_uuids = FxHashMap::default();
        for (clock_name, clock) in bctf_config.trace.typ.clock_types.iter() {
            // Make sure we have a stable clock UUID for time-domain
            let uuid = clock.uuid.unwrap_or_else(Uuid::new_v4);
            clock_uuids.insert(Intern::new(clock_name.clone()), uuid);
        }

        let mut timestamp_field_types = FxHashMap::default();
        for (stream_name, stream_cfg) in bctf_config.trace.typ.data_stream_types.iter() {
            timestamp_field_types.insert(
                Intern::new(stream_name.clone()),
                stream_cfg
                    .features
                    .event_record
                    .timestamp_field_type
                    .clone(),
            );
        }

        for (k, v) in bctf_config.trace.timeline_attrs() {
            common_timeline_attrs.insert(k, v);
        }

        let start_event = config
            .plugin
            .common_config()
            .start_event
            .as_ref()
            .map(|ev| Intern::new(ev.clone()));

        Self {
            client,
            common_timeline_attrs: common_timeline_attrs.into_iter().collect(),
            _config: config,
            known_timelines: Default::default(),
            current_timeline: None,
            start_event,
            clock_uuids,
            timestamp_field_types,
            streams_state: FxHashMap::default(),
        }
    }

    pub async fn close(self) -> Result<(), anyhow::Error> {
        let mut client = self.client;
        client.flush().await?;

        if let Ok(status) = client.status().await {
            debug!(
                events_received = status.events_received,
                events_written = status.events_written,
                events_pending = status.events_pending,
                "Ingest status"
            );
        }

        Ok(())
    }

    pub async fn handle_packet(&mut self, pkt: &Packet) -> Result<(), anyhow::Error> {
        // Check for restarts
        if let Some(start_event) = self.start_event {
            // Consider started if we have any streams
            if !self.streams_state.is_empty()
                && pkt.events.iter().any(|event| event.name == start_event)
            {
                warn!("Trace restart detected");
                self.streams_state.clear();
                self.current_timeline = None;
            }
        }

        let stream = match self.streams_state.entry(pkt.header.stream_id) {
            Entry::Vacant(v) => {
                // Use clock UUID as time domain
                let clock_uuid = pkt
                    .header
                    .clock_type
                    .and_then(|c| c.uuid)
                    .or_else(|| self.clock_uuids.get(&pkt.header.stream_name).cloned());
                let mut clock_attrs = if let Some(clock) = &pkt.header.clock_type {
                    clock.as_ref().timeline_attrs()
                } else {
                    vec![]
                };
                if let Some(clock) = &clock_uuid {
                    clock_attrs.push(("time_domain".into(), clock.to_string().into()));
                }

                v.insert(StreamState {
                    timestamp_tracker: self
                        .timestamp_field_types
                        .get(&pkt.header.stream_name)
                        .map(TrackingInstant::new)
                        .transpose()?,
                    clock_attrs,
                    event_count: 0,
                    packet_seqnum: None,
                    event_ordering: 0,
                })
            }
            Entry::Occupied(o) => o.into_mut(),
        };

        if let Some(events_discarded) = pkt.context.events_discarded {
            if events_discarded != 0 {
                warn!(events_discarded, "Detected discarded events");
                stream.event_count += events_discarded;
            }
        }

        if let Some(seqnum) = pkt.context.sequence_number {
            match stream.packet_seqnum {
                None => {
                    stream.packet_seqnum = seqnum.into();
                }
                Some(last_seqnum) => {
                    if (last_seqnum + 1) != seqnum {
                        warn!(last_seqnum, seqnum, "Unexpected packet sequence number");
                    } else if last_seqnum == seqnum {
                        warn!(last_seqnum, seqnum, "Duplicate packet sequence number");
                    }

                    stream.packet_seqnum = seqnum.into();
                }
            }
        }

        match self.known_timelines.get(&pkt.header.stream_id) {
            Some(tl_id) => {
                // It's a known timeline; switch to it if necessary
                if self.current_timeline != Some(*tl_id) {
                    self.client.switch_timeline(*tl_id).await?;
                    self.current_timeline = Some(*tl_id);
                }
            }
            None => {
                // We've never seen this timeline before; allocate an
                // id, and send its attrs.
                let tl_id = TimelineId::allocate();

                self.client.switch_timeline(tl_id).await?;
                self.current_timeline = Some(tl_id);

                let attrs: Vec<_> = self
                    .common_timeline_attrs
                    .iter()
                    .chain(stream.clock_attrs.iter())
                    .map(|(k, v)| (k.as_ref(), v.clone()))
                    //.chain(tl_key.timeline_attrs(&self.dbc))
                    .collect();
                self.client
                    .send_timeline_attrs(&pkt.header.stream_name, attrs)
                    .await?;
                self.known_timelines.insert(pkt.header.stream_id, tl_id);
            }
        };

        let pkt_header_attrs = pkt.header.event_attrs();
        let pkt_ctx_attrs = pkt.context.event_attrs();

        for event in pkt.events.iter() {
            let mut event_attrs = event.event_attrs();

            // Rollover tracking on raw cycles
            let timestamp = stream
                .timestamp_tracker
                .as_mut()
                .map(|t| t.elapsed(event.timestamp));
            if let Some(t) = timestamp {
                event_attrs.push(("internal.barectf.timestamp.cycles".into(), t.into()));

                // Nanosecond timestamp if we have a valid clock
                if let Some(clock) = pkt.header.clock_type.as_deref() {
                    if let Some(ns) = clock.timestamp_ns(t) {
                        event_attrs.push(("timestamp".into(), ns.into()));
                    }
                }
            }

            stream.event_count += 1;
            event_attrs.push((
                "internal.barectf.event.count".into(),
                stream.event_count.into(),
            ));

            let ev_attrs: Vec<_> = event_attrs
                .iter()
                .chain(pkt_header_attrs.iter())
                .chain(pkt_ctx_attrs.iter())
                .map(|(k, v)| (k.as_ref(), v.clone()))
                .collect();
            self.client
                .send_event(&event.name, stream.event_ordering, ev_attrs)
                .await?;

            stream.event_ordering += 1;
        }

        Ok(())
    }
}
