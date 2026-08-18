//! The REPL command interpreter: a faithful reimplementation of the C++
//! `ot-commissioner` CLI command surface, backed by the pure-Rust library.
//!
//! Commands that exercise the non-CCM commissioner protocol are fully wired
//! to [`mesh50::commissioner`]. Commands outside that scope (CCM
//! token flows, the persistent network registry, mDNS discovery, and
//! multi-network `--nwk`/`--dom` job execution) are present with their exact
//! usage and report `[failed]` with an explanatory message.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde_json::json;
use zeroize::Zeroizing;

use mesh50::{
    commissioner::{
        Commissioner, CommissionerDatasetFlags, CommissionerEvent, CommissionerState, DatasetFlags,
        ResultCode, StaticJoinerHandler,
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

// A commissioner operation owns the transport until its response arrives, so
// a keep-alive cannot safely be interleaved with an in-flight command. The
// longest current command paths can wait through multiple serial five-second
// MeshCoP receive windows plus an event-collection period. Reserving twenty
// seconds before dispatch keeps those bounded paths inside the minimum
// thirty-second keep-alive interval with scheduling/processing margin.
const COMMAND_KEEPALIVE_HEADROOM: Duration = Duration::from_secs(20);

/// One parsed REPL command line.
type Tokens = Vec<String>;

/// The REPL interpreter and its session state.
pub struct Interpreter {
    config: CliConfig,
    commissioner: Option<Commissioner>,
    /// Joiner PSKds keyed by joiner ID, applied via a [`StaticJoinerHandler`].
    joiner_pskds: HashMap<[u8; 8], Zeroizing<String>>,
    joiner_all_pskd: Option<Zeroizing<String>>,
    keepalive_deadline: Option<tokio::time::Instant>,
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
            joiner_pskds: HashMap::new(),
            joiner_all_pskd: None,
            keepalive_deadline: None,
            energy_reports: Vec::new(),
            panid_conflicts: Vec::new(),
            should_exit: false,
        }
    }

    /// Whether `exit`/`quit` has been requested.
    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    /// Returns the absolute deadline for the next application-driven
    /// commissioner keep-alive.
    pub(super) fn keepalive_deadline(&self) -> Option<tokio::time::Instant> {
        self.keepalive_deadline
    }

    /// Sends a scheduled or proactive keep-alive for the REPL loop.
    ///
    /// An accepted response re-arms the absolute deadline. Pending, rejected,
    /// and failed exchanges disconnect the unusable session so the application
    /// cannot continue without keep-alives.
    pub(super) async fn handle_scheduled_keepalive(&mut self) -> mesh50::Result<()> {
        self.keepalive_deadline = None;
        let (result, deferred_events, callback_result) = {
            let commissioner = self
                .commissioner
                .as_mut()
                .ok_or(mesh50::Error::InvalidState("commissioner is not started"))?;
            if commissioner.state() != CommissionerState::Active {
                return Err(mesh50::Error::InvalidState(
                    "commissioner session is not active",
                ));
            }

            let result = match commissioner.keep_alive().await {
                Ok(result) => result,
                Err(err) => {
                    commissioner.disconnect();
                    return Err(err);
                }
            };
            let mut deferred_events = Vec::new();
            let callback_result = loop {
                let event = match commissioner.next_event().await {
                    Ok(Some(event)) => event,
                    Ok(None) => {
                        commissioner.disconnect();
                        return Err(mesh50::Error::InvalidState(
                            "keep-alive response event was not queued",
                        ));
                    }
                    Err(err) => {
                        commissioner.disconnect();
                        return Err(err);
                    }
                };
                match event {
                    CommissionerEvent::KeepAliveResponse(callback_result) => {
                        break callback_result;
                    }
                    other => deferred_events.push(other),
                }
            };
            (result, deferred_events, callback_result)
        };

        for event in deferred_events {
            self.record_event(event);
        }
        if callback_result != result {
            if let Some(commissioner) = self.commissioner.as_mut() {
                commissioner.disconnect();
            }
            return Err(mesh50::Error::InvalidState(
                "keep-alive result and callback did not match",
            ));
        }
        match result {
            ResultCode::Accept => {
                self.schedule_keepalive();
                Ok(())
            }
            ResultCode::Pending => {
                if let Some(commissioner) = self.commissioner.as_mut() {
                    commissioner.disconnect();
                }
                Err(mesh50::Error::InvalidState(
                    "scheduled keep-alive response is pending",
                ))
            }
            ResultCode::Reject => {
                if let Some(commissioner) = self.commissioner.as_mut() {
                    commissioner.disconnect();
                }
                Err(mesh50::Error::InvalidState(
                    "scheduled keep-alive was rejected",
                ))
            }
        }
    }

    fn schedule_keepalive(&mut self) {
        self.keepalive_deadline = self
            .commissioner
            .as_ref()
            .filter(|commissioner| commissioner.state() == CommissionerState::Active)
            .and_then(|commissioner| {
                tokio::time::Instant::now().checked_add(commissioner.config().keepalive_interval)
            });
    }

    async fn refresh_keepalive_before_command(&mut self, tokens: &Tokens) -> mesh50::Result<()> {
        if !command_may_wait_for_commissioner(tokens) {
            return Ok(());
        }
        let Some(deadline) = self.keepalive_deadline else {
            return Ok(());
        };
        // A replacement start can spend several receive windows establishing
        // the new DTLS session, while the current commissioner remains active
        // until that attempt succeeds. Refresh it regardless of headroom.
        let starts_replacement = tokens.first().is_some_and(|token| token == "start");
        if !starts_replacement
            && deadline.saturating_duration_since(tokio::time::Instant::now())
                > COMMAND_KEEPALIVE_HEADROOM
        {
            return Ok(());
        }
        self.handle_scheduled_keepalive().await
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
        if let Err(err) = self.refresh_keepalive_before_command(&tokens).await {
            CommandValue::failed(format!("keep-alive failed: {err}")).print();
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
