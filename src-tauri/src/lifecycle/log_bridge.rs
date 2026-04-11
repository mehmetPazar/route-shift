//! Bridges phase/mechanism log events to Tauri's `log-line` event.
//!
//! The existing UI (ui/app.js) listens for three events:
//!   - `log-line`   — a single line of text, classified by keyword
//!   - `run-done`   — `{ mode, success, error? }` when an operation finishes
//!   - `tray-action` — unrelated (emitted from tray menu handlers)
//!
//! The log bridge is a thin wrapper that preserves the exact event names
//! and payload shapes so the UI behaves identically after the refactor.

use serde_json::json;
use tauri::{AppHandle, Emitter};

/// Event name for a single log line.
pub const LOG_LINE_EVENT: &str = "log-line";
/// Event name emitted when an Aç/Kapa/Test operation finishes.
pub const RUN_DONE_EVENT: &str = "run-done";

/// Emit a single log line to the UI. Silently ignores emit failures — the
/// only way `emit` fails is if the webview has been torn down, in which
/// case there is no receiver to care anyway.
pub fn emit_line(app: &AppHandle, line: impl Into<String>) {
    let _ = app.emit(LOG_LINE_EVENT, line.into());
}

/// Emit a success completion for the given mode ("add", "remove", "test", ...).
pub fn emit_done_ok(app: &AppHandle, mode: &str) {
    let _ = app.emit(
        RUN_DONE_EVENT,
        json!({
            "success": true,
            "mode": mode,
        }),
    );
}

/// Emit a failure completion for the given mode with an error message.
pub fn emit_done_err(app: &AppHandle, mode: &str, error: impl Into<String>) {
    let _ = app.emit(
        RUN_DONE_EVENT,
        json!({
            "success": false,
            "mode": mode,
            "error": error.into(),
        }),
    );
}
