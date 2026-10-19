// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The audit line as a JSON log writes it: every field survives a formatter
//! that flattens the event fields beside the event's metadata.

use std::error::Error as StdError;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use ferrohealth_smart::audit::AUDIT_TARGET;
use ferrohealth_smart::audit::AuditLine;
use http::Method;
use http::StatusCode;

/// A writer that keeps every byte a formatter writes.
#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("not poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn a_flattened_json_line_keeps_the_tracing_target_and_what_was_addressed()
-> Result<(), Box<dyn StdError>> {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(true)
        .with_writer(buffer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        AuditLine::new(&Method::GET, "read", StatusCode::OK)
            .on(Some("/fhir/{type}/{id}"), Some("Condition/c-1"))
            .write();
    });
    let bytes = buffer.0.lock().expect("not poisoned").clone();
    let line: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(AUDIT_TARGET, line["target"], "the event's own target");
    assert_eq!(
        "Condition/c-1", line["addressed"],
        "what the request addressed"
    );
    assert_eq!("read", line["interaction"]);
    Ok(())
}
