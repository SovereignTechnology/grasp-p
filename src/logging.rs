//! Application-specific tracing filters.

use tracing::{field::Visit, Event, Subscriber};
use tracing_subscriber::layer::{Context, Filter};

const LOCAL_RELAY_TARGET: &str = "nostr_sdk::local_relay::local::inner";
const UNCLEAN_RESET: &str = "WebSocket protocol error: Connection reset without closing handshake";

/// Expand a bare application level into an explicit `EnvFilter` directive.
///
/// `NGIT_LOG_LEVEL` is documented as the application log level. Applying a
/// bare level directly to `EnvFilter` also enables every dependency at that
/// level, which makes ordinary `info` deployments inherit verbose SDK and
/// protocol diagnostics. Keep dependencies at warnings for bare levels while
/// preserving explicit operator-authored filter expressions verbatim.
pub fn effective_log_filter(configured: &str) -> String {
    let trimmed = configured.trim();
    let level = trimmed.to_ascii_lowercase();
    if matches!(
        level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "off"
    ) {
        format!("warn,ngit_grasp={level}")
    } else {
        configured.to_string()
    }
}

/// Suppresses the routine unclean-disconnect event emitted by the embedded relay.
///
/// Internet clients commonly disappear without completing the WebSocket close
/// handshake. That is useful at debug level but is not a server failure. Match
/// the exact target and error text so database and outbound-send failures from
/// the same rust-nostr module remain visible at their original severity.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuppressRoutineDisconnects;

impl<S> Filter<S> for SuppressRoutineDisconnects
where
    S: Subscriber,
{
    fn enabled(&self, _meta: &tracing::Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _cx: &Context<'_, S>) -> bool {
        if event.metadata().target() != LOCAL_RELAY_TARGET {
            return true;
        }

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        !visitor
            .message
            .as_deref()
            .is_some_and(is_routine_disconnect_message)
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

fn is_routine_disconnect_message(message: &str) -> bool {
    message.contains("Can't handle websocket msg:") && message.contains(UNCLEAN_RESET)
}

#[cfg(test)]
mod tests {
    use super::{effective_log_filter, is_routine_disconnect_message};

    #[test]
    fn bare_levels_scope_verbose_output_to_ngit_grasp() {
        assert_eq!(effective_log_filter("debug"), "warn,ngit_grasp=debug");
        assert_eq!(effective_log_filter(" INFO "), "warn,ngit_grasp=info");
        assert_eq!(effective_log_filter("off"), "warn,ngit_grasp=off");
    }

    #[test]
    fn explicit_filter_expressions_remain_operator_controlled() {
        assert_eq!(
            effective_log_filter("ngit_grasp=debug,nostr_sdk=info"),
            "ngit_grasp=debug,nostr_sdk=info"
        );
        assert_eq!(
            effective_log_filter("debug,hyper=info,tokio=warn"),
            "debug,hyper=info,tokio=warn"
        );
    }

    #[test]
    fn identifies_reset_without_close_handshake() {
        assert!(is_routine_disconnect_message(
            "Can't handle websocket msg: WebSocket protocol error: Connection reset without closing handshake"
        ));
    }

    #[test]
    fn retains_other_websocket_and_relay_errors() {
        assert!(!is_routine_disconnect_message(
            "Can't handle websocket msg: WebSocket protocol error: invalid opcode"
        ));
        assert!(!is_routine_disconnect_message(
            "Can't save event into database: disk I/O error"
        ));
    }
}
