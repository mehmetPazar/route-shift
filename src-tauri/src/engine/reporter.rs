//! MechanismReporter — the channel through which parallel mechanism tasks
//! stream events back to the single state_writer loop.
//!
//! During Phase 3 Apply and Phase 6 Rollback, many mechanisms run in
//! parallel (kernel routes, PF anchor, networksetup, interface metric, etc.).
//! Each task holds a clone of a `MechanismReporter` and emits `MechanismEvent`s
//! as it progresses. A single `state_writer` task on the orchestrator side
//! drains the channel and serializes writes to `BypassState`, so there is
//! never any lock contention on the on-disk state file.
//!
//! All events also carry a freeform `detail` string that the orchestrator
//! forwards to the UI as `log-line` events, preserving the existing log
//! output format.

use crate::engine::types::{MechanismTag, ProxyState};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Which lifecycle phase produced this event. Useful for log formatting
/// and for filtering inside the state_writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Discovery,
    Plan,
    Apply,
    Verify,
    Commit,
    Rollback,
    VerifyRemoval,
    CommitRemoval,
}

/// Lifecycle of a single mechanism task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MechanismStatus {
    /// Task has started running. Not yet committed to state.
    Started,
    /// Task completed successfully. State should record this mechanism
    /// as applied so Kapa / reconcile know what to undo.
    Ok,
    /// Task completed but raised a non-fatal warning (e.g. pfctl printed
    /// a syntax warning while still loading the rules).
    Warn,
    /// Task failed. Orchestrator should abort Phase 3 and jump to Phase 6
    /// Rollback.
    Failed,
}

/// Concrete undo information emitted when a mechanism reports `Ok`.
///
/// Kapa and reconcile consume this to produce exact reverse operations.
/// Anything not captured here cannot be undone later — engines must
/// populate this carefully.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MechanismPayload {
    /// Kernel route table entries, CIDR strings ("160.79.104.0/24").
    KernelRoutes { cidrs: Vec<String> },
    /// macOS `networksetup -setadditionalroutes` entries — service name
    /// plus the (network, mask, gateway) triples that were installed.
    NetworksetupRoutes {
        service: String,
        entries: Vec<(String, String, String)>,
    },
    /// macOS PF anchor. `pf_conf_line_added = true` means we added the
    /// `anchor "com.routeshift"` line to /etc/pf.conf and must remove
    /// it on Kapa; `false` means it was already there and we leave it.
    PfAnchor {
        anchor: String,
        pf_conf_line_added: bool,
    },
    /// Windows interface metric change.
    /// `original` is whatever the interface had before — Kapa restores it.
    InterfaceMetric {
        index: u32,
        original: Option<u32>,
        new_metric: u32,
    },
    /// Proxy disable — capture whatever we overrode so Kapa can restore it.
    ProxyDisable { original: ProxyState },
    /// IPv6 policy change on an interface.
    Ipv6Policy {
        index: u32,
        original_enabled: bool,
    },
}

/// A single event from a mechanism task to the state writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MechanismEvent {
    pub tag: MechanismTag,
    pub phase: Phase,
    pub status: MechanismStatus,
    /// Freeform log message — forwarded to the UI as a `log-line` event.
    pub detail: String,
    /// Only populated when `status == Ok`. Contains enough information
    /// for Kapa to undo this exact mechanism.
    pub payload: Option<MechanismPayload>,
}

impl MechanismEvent {
    pub fn started(tag: MechanismTag, phase: Phase, detail: impl Into<String>) -> Self {
        Self {
            tag,
            phase,
            status: MechanismStatus::Started,
            detail: detail.into(),
            payload: None,
        }
    }

    pub fn ok(
        tag: MechanismTag,
        phase: Phase,
        detail: impl Into<String>,
        payload: MechanismPayload,
    ) -> Self {
        Self {
            tag,
            phase,
            status: MechanismStatus::Ok,
            detail: detail.into(),
            payload: Some(payload),
        }
    }

    pub fn warn(tag: MechanismTag, phase: Phase, detail: impl Into<String>) -> Self {
        Self {
            tag,
            phase,
            status: MechanismStatus::Warn,
            detail: detail.into(),
            payload: None,
        }
    }

    pub fn failed(tag: MechanismTag, phase: Phase, detail: impl Into<String>) -> Self {
        Self {
            tag,
            phase,
            status: MechanismStatus::Failed,
            detail: detail.into(),
            payload: None,
        }
    }
}

/// Thin wrapper around an `mpsc::UnboundedSender<MechanismEvent>`.
///
/// Cloneable and `Send` so every parallel mechanism task can hold its own
/// copy. Unbounded because event volume is tiny (tens of events per apply,
/// not thousands), and we never want a sender to block a mechanism task
/// waiting for the state_writer to drain.
#[derive(Clone)]
pub struct MechanismReporter {
    sender: mpsc::UnboundedSender<MechanismEvent>,
}

impl MechanismReporter {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<MechanismEvent>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    /// Send an event. Silently drops the event if the receiver has been
    /// closed — this is only possible if the state_writer task has already
    /// exited, in which case there is nothing meaningful to do anyway.
    pub fn emit(&self, event: MechanismEvent) {
        let _ = self.sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::MechanismTag;

    #[tokio::test]
    async fn reporter_round_trip() {
        let (reporter, mut rx) = MechanismReporter::new();
        reporter.emit(MechanismEvent::started(
            MechanismTag::KernelRoute,
            Phase::Apply,
            "kernel route task started",
        ));
        reporter.emit(MechanismEvent::ok(
            MechanismTag::KernelRoute,
            Phase::Apply,
            "kernel route task done",
            MechanismPayload::KernelRoutes {
                cidrs: vec!["8.8.8.8/32".into()],
            },
        ));
        drop(reporter);

        let mut got = Vec::new();
        while let Some(ev) = rx.recv().await {
            got.push(ev);
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].status, MechanismStatus::Started);
        assert_eq!(got[1].status, MechanismStatus::Ok);
    }
}
