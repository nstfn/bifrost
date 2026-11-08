//! Flow control for entertainment frames: latest frame wins, one frame in
//! flight.
//!
//! zigbee-herdsman sends to one device one request at a time, and queues the
//! rest. At ~52 ms per frame to a gradient strip, one light takes ~16-19
//! frames/s, while the TV sends ~49 frames/s. When the radio slows down, a
//! fire-and-forget sender fills that queue and the light shows the picture
//! seconds (we measured 17 s) late.
//!
//! [`FrameFlow`] holds back each frame until zigbee2mqtt reports that the
//! previous one completed (the "ack"), and keeps only the latest frame while
//! it waits. The queue in zigbee-herdsman then never holds more than
//! [`MAX_IN_FLIGHT`] frames.
//!
//! Pure state machine: no I/O, the caller passes the clock.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// A frame without an ack after this delay may have lost its ack.
///
/// zigbee2mqtt can skip a log line, or the ack can arrive unparsable. One
/// more frame may then go out, so a lost ack does not freeze the light. Six
/// times the ~52 ms that a frame takes when the radio is healthy.
pub const SOFT_DEADLINE: Duration = Duration::from_millis(300);

/// A frame without an ack after this delay is forgotten: zigbee-herdsman has
/// completed or dropped it long ago (Bifrost sends frames with a 100 ms
/// timeout and no recovery).
pub const HARD_DEADLINE: Duration = Duration::from_secs(2);

/// At most this many frames younger than [`HARD_DEADLINE`] are in flight.
/// With no ack at all, the rate falls to ~1 frame/s and the queue in
/// zigbee-herdsman still cannot grow.
pub const MAX_IN_FLIGHT: usize = 2;

/// Frames sent for this long without one successful ack trigger a warning:
/// the flow then runs at ~1 frame/s.
pub const NO_ACK_WARNING: Duration = Duration::from_secs(5);

/// Prefix of the info line that zigbee-herdsman-converters logs (namespace
/// `zhc:tz`) after a `zclcommand` with `"logging": true` completes:
/// `Invoked ZCL command <cluster>.<command> with payload '<json>'`.
pub const INVOKED_PREFIX: &str = "Invoked ZCL command";
const PAYLOAD_MARKER: &str = "with payload '";

/// Result of an ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    /// No frame in flight matches this ack.
    Unmatched,
    /// The ack removed at least one frame. `first` is true for the first
    /// successful ack since the last [`FrameFlow::reset`].
    Matched { first: bool },
}

#[derive(Debug)]
pub struct FrameFlow<T> {
    pending: Option<T>,
    /// Frames sent and not acked yet, oldest first: (frame data, sent at).
    in_flight: VecDeque<(Vec<u8>, Instant)>,
    first_sent: Option<Instant>,
    acked: bool,
    warned: bool,
}

impl<T> Default for FrameFlow<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FrameFlow<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: None,
            in_flight: VecDeque::new(),
            first_sent: None,
            acked: false,
            warned: false,
        }
    }

    /// Forget all state. Call on stream start and stop.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Store `frame` as the next frame to send. It replaces any frame that
    /// is still waiting.
    pub fn set_pending(&mut self, frame: T) {
        self.pending = Some(frame);
    }

    /// Take the waiting frame. Call only after [`Self::may_send`] said yes.
    pub const fn take_pending(&mut self) -> Option<T> {
        self.pending.take()
    }

    fn expire(&mut self, now: Instant) {
        while let Some((_, sent_at)) = self.in_flight.front() {
            if now.saturating_duration_since(*sent_at) < HARD_DEADLINE {
                break;
            }
            self.in_flight.pop_front();
        }
    }

    /// True when a frame waits, no frame in flight is younger than
    /// [`SOFT_DEADLINE`], and fewer than [`MAX_IN_FLIGHT`] frames are younger
    /// than [`HARD_DEADLINE`]. Drops the frames older than
    /// [`HARD_DEADLINE`].
    pub fn may_send(&mut self, now: Instant) -> bool {
        self.expire(now);

        if self.pending.is_none() || self.in_flight.len() >= MAX_IN_FLIGHT {
            return false;
        }

        self.in_flight
            .back()
            .is_none_or(|(_, sent_at)| now.saturating_duration_since(*sent_at) >= SOFT_DEADLINE)
    }

    /// Record a frame sent at `now`, with its zigbee data bytes.
    pub fn sent(&mut self, data: Vec<u8>, now: Instant) {
        self.first_sent.get_or_insert(now);
        self.in_flight.push_back((data, now));
    }

    /// Successful ack for the frame with these data bytes. zigbee-herdsman
    /// completes the requests to one device in order, so every older frame
    /// is gone too.
    pub fn ack_data(&mut self, data: &[u8]) -> Ack {
        let Some(pos) = self.in_flight.iter().position(|(d, _)| d == data) else {
            return Ack::Unmatched;
        };
        self.in_flight.drain(..=pos);

        let first = !self.acked;
        self.acked = true;
        Ack::Matched { first }
    }

    /// Failed frame (the error line names no data): remove the oldest one.
    pub fn ack_failure(&mut self) -> Ack {
        if self.in_flight.pop_front().is_some() {
            Ack::Matched { first: false }
        } else {
            Ack::Unmatched
        }
    }

    /// Earliest instant after `now` at which [`Self::may_send`] can become
    /// true or a frame in flight expires, if any. Never returns an instant
    /// at or before `now`, so a timer on it cannot spin.
    #[must_use]
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        let expiry = self.in_flight.front().map(|(_, t)| *t + HARD_DEADLINE);

        let send = if self.pending.is_some() {
            let soft = self.in_flight.back().map(|(_, t)| *t + SOFT_DEADLINE);
            let room = self
                .in_flight
                .len()
                .checked_sub(MAX_IN_FLIGHT)
                .and_then(|idx| self.in_flight.get(idx))
                .map(|(_, t)| *t + HARD_DEADLINE);
            soft.max(room)
        } else {
            None
        };

        [expiry, send]
            .into_iter()
            .flatten()
            .filter(|t| *t > now)
            .min()
    }

    /// True once per stream, when frames went out for [`NO_ACK_WARNING`]
    /// without one successful ack.
    pub fn no_ack_warning_due(&mut self, now: Instant) -> bool {
        let due = !self.acked
            && !self.warned
            && self
                .first_sent
                .is_some_and(|t| now.saturating_duration_since(t) >= NO_ACK_WARNING);
        if due {
            self.warned = true;
        }
        due
    }
}

#[derive(Deserialize)]
struct ZclPayload {
    data: Vec<u8>,
}

/// Data bytes of the frame named in an `Invoked ZCL command ... with payload
/// '{"data":[...]}'` log line, if `message` is one.
#[must_use]
pub fn parse_invoked(message: &str) -> Option<Vec<u8>> {
    let rest = message.strip_prefix(INVOKED_PREFIX)?;
    let start = rest.find(PAYLOAD_MARKER)? + PAYLOAD_MARKER.len();
    let json = rest[start..].strip_suffix('\'')?;
    serde_json::from_str::<ZclPayload>(json)
        .ok()
        .map(|payload| payload.data)
}

/// Namespace and text of a `bridge/logging` line.
///
/// Newer zigbee2mqtt sends the namespace in its own field. zigbee2mqtt 2.14.3
/// (on HAOS, 2026-11-08) has no such field and puts it at the start of the
/// message instead: `"zhc:tz: Invoked ZCL command ..."`,
/// `"z2m: Publish 'set' ..."` (captured on its websocket). Without this, no
/// ack matched and the flow fell to ~1 frame/s.
#[must_use]
pub fn split_log<'a>(namespace: Option<&'a str>, message: &'a str) -> (Option<&'a str>, &'a str) {
    if namespace.is_some() {
        return (namespace, message);
    }
    match message.split_once(": ") {
        Some((head, text)) if !head.is_empty() && !head.contains(char::is_whitespace) => {
            (Some(head), text)
        }
        _ => (None, message),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_invoked, split_log};

    #[test]
    fn split_log_reads_both_zigbee2mqtt_formats() {
        // As captured from zigbee2mqtt 2.14.3: namespace inside the message.
        let msg = "zhc:tz: Invoked ZCL command 64513.1 with payload '{\"data\":[38,0,0,0,170,6]}'";
        let (ns, text) = split_log(None, msg);
        assert_eq!(ns, Some("zhc:tz"));
        assert_eq!(parse_invoked(text), Some(vec![38, 0, 0, 0, 170, 6]));

        let msg = "z2m: Publish 'set' 'zclcommand' to 'Hue Play gradient - TV' failed: 'Error'";
        let (ns, text) = split_log(None, msg);
        assert_eq!(ns, Some("z2m"));
        assert!(text.starts_with("Publish 'set' 'zclcommand' to 'Hue Play gradient - TV' failed"));

        // Newer zigbee2mqtt: namespace in its own field, message untouched.
        let msg = "Invoked ZCL command 64513.1 with payload '{\"data\":[1]}'";
        assert_eq!(split_log(Some("zhc:tz"), msg), (Some("zhc:tz"), msg));

        // A message without a namespace prefix stays whole.
        assert_eq!(
            split_log(None, "plain text: here"),
            (None, "plain text: here")
        );
    }
}
