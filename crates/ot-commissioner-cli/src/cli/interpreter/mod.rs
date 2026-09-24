//! The REPL command interpreter: a faithful reimplementation of the C++
//! `ot-commissioner` CLI command surface, backed by the pure-Rust library.
//!
//! Commands that exercise the non-CCM commissioner protocol are fully wired
//! to [`meshcop::commissioner`]. Commands outside that scope (CCM
//! token flows, the persistent network registry, mDNS discovery, and
//! multi-network `--nwk`/`--dom` job execution) are present with their exact
//! usage and report `[failed]` with an explanatory message.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde_json::json;
use zeroize::Zeroizing;

use meshcop::{
    commissioner::{
        Commissioner, CommissionerDatasetFlags, CommissionerEvent, DatasetFlags, Events,
        SessionStatus, StaticJoinerHandler,
    },
    crypto::compute_joiner_id,
    dataset::Dataset,
    meshcop::diag::{NetDiagData, diag_flags},
};

use super::config::CliConfig;
use super::json;
use super::value::CommandValue;

const SYNTAX_FEW_ARGS: &str = "too few arguments";
const NOT_CONNECTED: &str = "commissioner is not started; run 'start' first";

/// One parsed REPL command line.
type Tokens = Vec<String>;

/// The REPL interpreter and its session state.
pub struct Interpreter {
    config: CliConfig,
    commissioner: Option<Commissioner>,
    /// Events of the current session; `None` once the stream has ended.
    events: Option<Events>,
    /// Joiner PSKds keyed by joiner ID, applied via a [`StaticJoinerHandler`].
    joiner_pskds: HashMap<[u8; 8], Zeroizing<String>>,
    joiner_all_pskd: Option<Zeroizing<String>>,
    energy_reports: Vec<(String, u32, Vec<u8>)>,
    panid_conflicts: Vec<(String, u32, u16)>,
    should_exit: bool,
}

impl Interpreter {
    /// Creates an interpreter from the loaded configuration.
    pub fn new(config: CliConfig) -> Self {
        Self {
            config,
            commissioner: None,
            events: None,
            joiner_pskds: HashMap::new(),
            joiner_all_pskd: None,
            energy_reports: Vec::new(),
            panid_conflicts: Vec::new(),
            should_exit: false,
        }
    }

    /// Whether `exit`/`quit` has been requested.
    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    /// Resigns a running session before the program exits, printing the
    /// outcome. Does nothing without one.
    pub async fn shutdown(&mut self) {
        let running = self.commissioner.as_ref().is_some_and(|commissioner| {
            !matches!(commissioner.status(), SessionStatus::Closed { .. })
        });
        if running {
            self.cmd_stop().await.print();
        }
    }

    /// Waits for the current session's next event. Never completes while no
    /// session is running, so the REPL can wait on it alongside input.
    pub(super) async fn next_event(&mut self) -> Option<CommissionerEvent> {
        let Some(events) = self.events.as_mut() else {
            return std::future::pending().await;
        };
        let event = events.next().await;
        if event.is_none() {
            self.events = None;
        }
        event
    }

    /// Records an event that arrived while the REPL was waiting for input,
    /// and returns a message to show for a lost session or lost events.
    pub(super) fn handle_background_event(&mut self, event: CommissionerEvent) -> Option<String> {
        if let CommissionerEvent::SessionLost { reason } = &event {
            return Some(format!("commissioner session lost: {reason}"));
        }
        self.record_event(event)
    }

    /// Evaluates one input line and prints the result.
    pub async fn evaluate_and_print(&mut self, line: &str) {
        let tokens = match tokenize(line) {
            Ok(tokens) => tokens,
            Err(message) => {
                CommandValue::failed(message).print();
                return;
            }
        };
        let tokens = Zeroizing::new(tokens);
        if tokens.is_empty() {
            return;
        }
        if has_multi_network_flag(&tokens) {
            CommandValue::failed(
                "multi-network selectors (--nwk/--dom) require the network registry, \
                 which is not implemented in this build",
            )
            .print();
            return;
        }
        let value = self.dispatch(&tokens).await;
        value.print();
    }

    async fn dispatch(&mut self, tokens: &Tokens) -> CommandValue {
        match tokens[0].as_str() {
            "help" => self.cmd_help(tokens),
            "exit" | "quit" => {
                self.should_exit = true;
                CommandValue::done()
            }
            "config" => self.cmd_config(tokens),
            "state" => self.cmd_state(),
            "start" => self.cmd_start(tokens).await,
            "stop" => self.cmd_stop().await,
            "active" => self.cmd_active(),
            "sessionid" => self.cmd_sessionid(),
            "borderagent" => self.cmd_border_agent(tokens).await,
            "joiner" => self.cmd_joiner(tokens).await,
            "commdataset" => self.cmd_comm_dataset(tokens).await,
            "opdataset" => self.cmd_op_dataset(tokens).await,
            "bbrdataset" => self.cmd_bbr_dataset(tokens).await,
            "reenroll" => self.cmd_managed(tokens, ManagedCommand::Reenroll).await,
            "domainreset" => self.cmd_managed(tokens, ManagedCommand::DomainReset).await,
            "migrate" => self.cmd_managed(tokens, ManagedCommand::Migrate).await,
            "mlr" => self.cmd_mlr(tokens).await,
            "announce" => self.cmd_announce(tokens).await,
            "panid" => self.cmd_panid(tokens).await,
            "energy" => self.cmd_energy(tokens).await,
            "netdiag" => self.cmd_netdiag(tokens).await,
            // Out-of-scope C++ CLI features, surfaced with their usage.
            "token" => CommandValue::failed("CCM token support is not implemented in this build"),
            "br" | "domain" | "network" => CommandValue::failed(
                "the persistent network registry is not implemented in this build",
            ),
            other => CommandValue::failed(format!(
                "'{other}' is not a valid command, type 'help' to list all commands"
            )),
        }
    }
}

mod datasets;
mod joiner;
mod management;
mod misc;
mod network_diagnostics;
mod session;

mod support;

use support::*;

#[cfg(test)]
mod tests;
