use hue::zigbee::ZigbeeMessage;
use serde_json::{Value, json};

/// Use the low-level endpoint for `Zigbee2MQTT`, which allows free-form zigbee
/// messages to be sent.
///
/// NOTE: The generated z2m payload only works on z2m instances with
/// Zigbee-Herdsman-Converter version 23.0.0 or greater.
///
/// This is the case for z2m version 2.1.1 and newer.
///
/// Older versions WILL NOT WORK.
#[must_use]
pub fn hue_zclcommand(msg: &ZigbeeMessage) -> Value {
    json!({
        "zclcommand": {
            "cluster": msg.cluster,
            "command": msg.command,
            "payload": {
                "data": msg.data,
            },
            "frametype": msg.frametype,
            "options": {
                "manufacturerCode": msg.mfc,
                "disableDefaultResponse": msg.ddr,
                "direction": 0,
                "timeout": 100.0,
            },
        }
    })
}

/// [`hue_zclcommand`] for one entertainment frame: a failed frame is dropped,
/// not retried.
///
/// zigbee-herdsman sends to one device one request at a time. When a delivery
/// fails with a "recoverable" error (`MAC_NO_ACK`, `NWK_NO_ROUTE`,
/// `MAC_CHANNEL_ACCESS_FAILURE`, `BUFFER_FULL`, ...), its recovery waits 2 s,
/// rediscovers the route or the network address and tries again, up to 5
/// attempts, and logs nothing above debug level when an attempt succeeds.
/// Every later frame for that light waits behind it, so the light shows the
/// picture seconds late until the queue drains, and the queue drains slowly
/// (with a CC2652P coordinator over TCP we measured ~52 ms per frame, so at
/// most ~19 frames/s to one light, close to the stream rate). A frame is stale one interval later: dropping it costs
/// one interval, and the next frame follows. Reset and segment mapping keep
/// the recovery (see `zStackAdapter.sendZclFrameToEndpointInternal`,
/// zigbee-herdsman 11.2.0).
///
/// `"logging": true` makes zigbee-herdsman-converters log `Invoked ZCL
/// command ... with payload '{"data":[...]}'` at info level once the frame
/// completes. zigbee2mqtt forwards that line on `bridge/logging`, and Bifrost
/// uses it as the ack that lets the next frame go (see
/// [`crate::backend::z2m::flow`]).
#[must_use]
pub fn hue_entertainment_zclcommand(msg: &ZigbeeMessage) -> Value {
    let mut req = hue_zclcommand(msg);
    req["zclcommand"]["options"]["disableRecovery"] = Value::Bool(true);
    req["zclcommand"]["logging"] = Value::Bool(true);
    req
}

#[cfg(test)]
mod tests {
    use hue::zigbee::ZigbeeMessage;
    use serde_json::Value;

    use super::{hue_entertainment_zclcommand, hue_zclcommand};

    fn options(req: &Value) -> &serde_json::Map<String, Value> {
        req["zclcommand"]["options"].as_object().unwrap()
    }

    #[test]
    fn entertainment_frame_disables_recovery() {
        let msg = ZigbeeMessage::new(0xFC01, 1, vec![0x01, 0x02]);
        let req = hue_entertainment_zclcommand(&msg);

        assert_eq!(options(&req)["disableRecovery"], Value::Bool(true));
    }

    #[test]
    fn entertainment_frame_keeps_the_plain_command() {
        let msg = ZigbeeMessage::new(0xFC01, 1, vec![0x01, 0x02]);
        let mut frame = hue_entertainment_zclcommand(&msg);
        frame["zclcommand"]["options"]
            .as_object_mut()
            .unwrap()
            .remove("disableRecovery");
        frame["zclcommand"]
            .as_object_mut()
            .unwrap()
            .remove("logging");

        assert_eq!(frame, hue_zclcommand(&msg));
    }

    #[test]
    fn plain_command_keeps_recovery() {
        let msg = ZigbeeMessage::new(0xFC01, 3, vec![]);
        let req = hue_zclcommand(&msg);

        assert!(!options(&req).contains_key("disableRecovery"));
    }
}
