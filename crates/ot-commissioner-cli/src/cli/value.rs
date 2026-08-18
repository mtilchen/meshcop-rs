//! The result of evaluating one REPL command and its `[done]`/`[failed]`
//! rendering, mirroring the C++ `Interpreter::Value` and `Print`.

use zeroize::Zeroizing;

use super::console::{self, Color};

/// A command result: either a (possibly empty) success payload or an error
/// message.
pub struct CommandValue {
    body: Zeroizing<String>,
    failed: bool,
}

impl CommandValue {
    /// A success result carrying `data` (printed before `[done]`).
    pub fn ok(data: impl Into<String>) -> Self {
        Self {
            body: Zeroizing::new(data.into()),
            failed: false,
        }
    }

    /// A success result with no payload (just `[done]`).
    pub fn done() -> Self {
        Self::ok(String::new())
    }

    /// A failure result carrying `message` (printed before `[failed]`).
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            body: Zeroizing::new(message.into()),
            failed: true,
        }
    }

    /// Renders the body followed by the `[done]`/`[failed]` marker (without
    /// color), matching the C++ `Interpreter::PrintOrExport` text.
    pub(crate) fn rendered(&self) -> Zeroizing<String> {
        let mut output = Zeroizing::new(self.body.to_string());
        if !output.is_empty() {
            output.push('\n');
        }
        *output += if self.failed { "[failed]" } else { "[done]" };
        output
    }

    /// Prints the value followed by the `[done]`/`[failed]` marker, matching
    /// the C++ `Interpreter::Print`.
    pub fn print(&self) {
        let color = if self.failed {
            Color::Red
        } else {
            Color::Green
        };
        let rendered = self.rendered();
        console::write(&rendered, color);
    }
}

impl From<meshcop::Result<()>> for CommandValue {
    fn from(result: meshcop::Result<()>) -> Self {
        match result {
            Ok(()) => CommandValue::done(),
            Err(err) => CommandValue::failed(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn done_renders_just_the_marker() {
        assert_eq!(CommandValue::done().rendered().as_str(), "[done]");
    }

    #[test]
    fn ok_renders_body_then_done() {
        assert_eq!(
            CommandValue::ok("value").rendered().as_str(),
            "value\n[done]"
        );
    }

    #[test]
    fn failed_renders_message_then_failed() {
        assert_eq!(
            CommandValue::failed("boom").rendered().as_str(),
            "boom\n[failed]"
        );
    }

    #[test]
    fn from_result_maps_ok_to_done_and_err_to_failed() {
        let ok: CommandValue = Ok(()).into();
        assert_eq!(ok.rendered().as_str(), "[done]");
        let err: CommandValue = Err(meshcop::Error::Unsupported("nope")).into();
        assert_eq!(
            err.rendered().as_str(),
            "unsupported operation: nope\n[failed]"
        );
    }
}
