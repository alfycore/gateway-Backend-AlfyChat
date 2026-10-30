//! Dates au format `Date.prototype.toISOString()` (millisecondes, suffixe `Z`).

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serializer;

pub fn to_string(d: &DateTime<Utc>) -> String {
    d.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn ser<S: Serializer>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&to_string(d))
}

pub fn ser_opt<S: Serializer>(d: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_str(&to_string(d)),
        None => s.serialize_none(),
    }
}
