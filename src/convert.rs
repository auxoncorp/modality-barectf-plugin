use auxon_sdk::api::{AttrKey, AttrVal, Nanoseconds};
use barectf_parser::{
    ClockType, Event, FieldValue, LogLevel, PacketContext, PacketHeader, PrimitiveFieldValue,
    Timestamp, Trace,
};

// Array types are capped at 10 elements
const MAX_ARRAY_LEN: usize = 10;

pub trait ClockExt {
    const ONE_SECOND: u128 = 1_000_000_000;

    fn frequency(&self) -> Option<u64>;

    fn timestamp_ns(&self, cycles: Timestamp) -> Option<Nanoseconds> {
        let cycles_x_ns = u128::from(cycles) * Self::ONE_SECOND;
        self.frequency()
            .map(|f| Nanoseconds::from((cycles_x_ns / u128::from(f)) as u64))
    }
}

impl ClockExt for ClockType {
    fn frequency(&self) -> Option<u64> {
        if self.frequency == 0 {
            None
        } else {
            Some(self.frequency)
        }
    }
}

pub trait TimelineExt {
    fn timeline_attrs(&self) -> Vec<(AttrKey, AttrVal)>;
}

impl TimelineExt for ClockType {
    fn timeline_attrs(&self) -> Vec<(AttrKey, AttrVal)> {
        let mut attrs = Vec::new();

        attr("clock.frequency", self.frequency, &mut attrs);
        opt_attr(
            "clock.offset.seconds",
            self.offset.as_ref().map(|o| o.seconds),
            &mut attrs,
        );
        opt_attr(
            "clock.offset.cycles",
            self.offset.as_ref().map(|o| o.cycles),
            &mut attrs,
        );
        attr(
            "clock.origin_is_unix_epoch",
            self.origin_is_unix_epoch,
            &mut attrs,
        );
        attr("clock.precision", self.precision, &mut attrs);
        opt_attr("clock.uuid", self.uuid.map(|id| id.to_string()), &mut attrs);
        opt_attr("clock.description", self.description.as_ref(), &mut attrs);
        attr("clock.c_type", self.c_type.as_str(), &mut attrs);
        if self.origin_is_unix_epoch {
            attr("clock_style", "absolute", &mut attrs);
        } else {
            attr("clock_style", "relative", &mut attrs);
        }

        attrs
    }
}

impl TimelineExt for Trace {
    // This just produces the environment variables currently
    fn timeline_attrs(&self) -> Vec<(AttrKey, AttrVal)> {
        let mut attrs = Vec::new();

        for (k, v) in self.environment.iter() {
            let val: AttrVal = match v {
                serde_yaml::Value::String(s) => s.into(),
                serde_yaml::Value::Number(n) => {
                    if let Some(n) = n.as_i64() {
                        n.into()
                    } else if let Some(n) = n.as_u64() {
                        n.into()
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            attr(format!("environment.{}", k), val, &mut attrs);
        }

        attrs
    }
}

pub trait EventExt {
    fn event_attrs(&self) -> Vec<(AttrKey, AttrVal)>;
}

impl EventExt for PacketHeader {
    fn event_attrs(&self) -> Vec<(AttrKey, AttrVal)> {
        let mut attrs = Vec::new();

        opt_attr(
            "packet_header.trace_uuid",
            self.trace_uuid.map(|id| id.to_string()),
            &mut attrs,
        );
        attr("packet_header.stream.id", self.stream_id, &mut attrs);
        attr(
            "packet_header.stream.name",
            self.stream_name.as_str(),
            &mut attrs,
        );

        attrs
    }
}

impl EventExt for PacketContext {
    fn event_attrs(&self) -> Vec<(AttrKey, AttrVal)> {
        let mut attrs = Vec::new();

        attr(
            "packet_context.packet_size.bits",
            self.packet_size_bits as u64,
            &mut attrs,
        );
        attr(
            "packet_context.packet_size.bytes",
            self.packet_size() as u64,
            &mut attrs,
        );
        attr(
            "packet_context.content_size.bits",
            self.content_size_bits as u64,
            &mut attrs,
        );
        attr(
            "packet_context.content_size.bytes",
            self.content_size() as u64,
            &mut attrs,
        );
        opt_attr(
            "packet_context.beginning_timestamp",
            self.beginning_timestamp,
            &mut attrs,
        );
        opt_attr(
            "packet_context.end_timestamp",
            self.end_timestamp,
            &mut attrs,
        );
        opt_attr(
            "packet_context.events_discarded",
            self.events_discarded,
            &mut attrs,
        );
        opt_attr(
            "packet_context.sequence_number",
            self.sequence_number,
            &mut attrs,
        );

        for (field, val) in self.extra_members.iter() {
            fv_attrs(Some("packet_context"), field.as_str(), val, &mut attrs);
        }

        attrs
    }
}

impl EventExt for Event {
    fn event_attrs(&self) -> Vec<(AttrKey, AttrVal)> {
        let mut attrs = Vec::new();

        attr("internal.barectf.event.id", self.id, &mut attrs);
        attr(
            "internal.barectf.event.name",
            self.name.as_str(),
            &mut attrs,
        );
        attr("name", self.name.as_str(), &mut attrs);
        attr("internal.barectf.clock.cycles", self.timestamp, &mut attrs);
        match self.log_level {
            None => {}
            Some(LogLevel::Other(ll)) => {
                attr("log_level", ll, &mut attrs);
            }
            Some(ll) => {
                attr("log_level", ll.to_string(), &mut attrs);
            }
        }

        // Common context
        for (field, val) in self.common_context.iter() {
            fv_attrs(Some("common_context"), field.as_str(), val, &mut attrs);
        }

        // Specific context
        for (field, val) in self.specific_context.iter() {
            fv_attrs(Some("specific_context"), field.as_str(), val, &mut attrs);
        }

        // Payload
        for (field, val) in self.payload.iter() {
            fv_attrs(None, field.as_str(), val, &mut attrs);
        }

        attrs
    }
}

fn attr<K: Into<AttrKey>, V: Into<AttrVal>>(k: K, v: V, attrs: &mut Vec<(AttrKey, AttrVal)>) {
    attrs.push((k.into(), v.into()));
}

fn opt_attr<K: Into<AttrKey>, V: Into<AttrVal>>(
    k: K,
    v: Option<V>,
    attrs: &mut Vec<(AttrKey, AttrVal)>,
) {
    if let Some(val) = v {
        attrs.push((k.into(), val.into()));
    }
}

fn pfv_attrs(key: String, pfv: &PrimitiveFieldValue, attrs: &mut Vec<(AttrKey, AttrVal)>) {
    match pfv {
        PrimitiveFieldValue::UnsignedInteger(v, _) => {
            attr(key, *v, attrs);
        }
        PrimitiveFieldValue::SignedInteger(v, _) => {
            attr(key, *v, attrs);
        }
        PrimitiveFieldValue::String(v) => {
            attr(key, v, attrs);
        }
        PrimitiveFieldValue::F32(v) => {
            attr(key, v.0, attrs);
        }
        PrimitiveFieldValue::F64(v) => {
            attr(key, v.0, attrs);
        }
        PrimitiveFieldValue::Enumeration(v, _, maybe_label) => {
            attr(format!("{}.container", key), *v, attrs);
            if let Some(label) = maybe_label.as_ref().map(|s| s.as_str()) {
                attr(key, label, attrs);
            }
        }
    }
}

fn format_key(prefix: Option<&str>, field_name: &str) -> String {
    if let Some(p) = prefix {
        format!("{}.{}", p, field_name)
    } else {
        field_name.to_string()
    }
}

fn fv_attrs(
    prefix: Option<&str>,
    field_name: &str,
    fv: &FieldValue,
    attrs: &mut Vec<(AttrKey, AttrVal)>,
) {
    let key = format_key(prefix, field_name);
    match fv {
        FieldValue::Primitive(pfv) => {
            pfv_attrs(key, pfv, attrs);
        }
        FieldValue::Array(arr) => {
            for (idx, elem) in arr.iter().enumerate() {
                pfv_attrs(format!("{}.array.{}", key, idx), elem, attrs);
                if (idx + 1) == MAX_ARRAY_LEN {
                    break;
                }
            }
        }
    }
}
