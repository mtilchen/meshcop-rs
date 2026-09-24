use super::*;

impl Interpreter {
    // --- help ---

    pub(super) fn cmd_help(&self, tokens: &Tokens) -> CommandValue {
        if tokens.len() == 1 {
            let mut names: Vec<&str> = COMMANDS.iter().map(|(name, _)| *name).collect();
            names.sort_unstable();
            let mut data = String::new();
            for name in names {
                data.push_str(name);
                data.push('\n');
            }
            data.push_str("\ntype 'help <command>' for help of specific command.");
            CommandValue::ok(data)
        } else {
            match COMMANDS.iter().find(|(name, _)| *name == tokens[1]) {
                Some((_, usage)) => CommandValue::ok(format!("usage:\n{usage}")),
                None => CommandValue::failed(format!("{} is not a valid command", tokens[1])),
            }
        }
    }

    /// Drains commissioner events for up to `duration`, storing energy reports
    /// and PAN-ID conflicts for the later `energy report` / `panid conflict`.
    /// Returns the command result: a warning when events were lost.
    pub(super) async fn pump_events(&mut self, duration: Duration) -> CommandValue {
        let deadline = tokio::time::Instant::now() + duration;
        let mut warnings = Vec::new();
        while let Some(events) = self.events.as_mut() {
            match tokio::time::timeout_at(deadline, events.next()).await {
                Ok(Some(event)) => warnings.extend(self.record_event(event)),
                Ok(None) => self.events = None,
                Err(_) => break,
            }
        }
        CommandValue::ok(warnings.join("\n"))
    }

    /// Stores scan reports, and returns a warning when events were lost.
    pub(super) fn record_event(&mut self, event: CommissionerEvent) -> Option<String> {
        match event {
            CommissionerEvent::EnergyReport {
                peer_addr,
                channel_mask,
                energy_list,
            } => self
                .energy_reports
                .push((peer_addr, channel_mask, energy_list)),
            CommissionerEvent::PanIdConflict {
                peer_addr,
                channel_mask,
                pan_id,
            } => self.panid_conflicts.push((peer_addr, channel_mask, pan_id)),
            CommissionerEvent::Lagged { missed } => {
                return Some(format!(
                    "missed {missed} commissioner events; energy and PAN ID reports may be incomplete"
                ));
            }
            _ => {}
        }
        None
    }
}
