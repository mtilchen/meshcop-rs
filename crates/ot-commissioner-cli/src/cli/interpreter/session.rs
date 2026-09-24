use super::*;

impl Interpreter {
    // --- session lifecycle ---

    pub(super) fn cmd_state(&self) -> CommandValue {
        let status = self.commissioner.as_ref().map(Commissioner::status);
        CommandValue::ok(match status {
            Some(SessionStatus::Connected | SessionStatus::Idle) => "connected",
            Some(SessionStatus::Petitioning) => "petitioning",
            Some(SessionStatus::Active { .. }) => "active",
            // A closed session and any future status read as disabled.
            None | Some(_) => "disabled",
        })
    }

    pub(super) fn cmd_active(&self) -> CommandValue {
        let active = self
            .commissioner
            .as_ref()
            .is_some_and(|c| c.status().is_active());
        CommandValue::ok(if active { "true" } else { "false" })
    }

    pub(super) fn cmd_sessionid(&self) -> CommandValue {
        match self.commissioner.as_ref().and_then(|c| c.session_id()) {
            Some(id) => CommandValue::ok(id.to_string()),
            None => CommandValue::failed("commissioner session is not active"),
        }
    }

    pub(super) async fn cmd_start(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let connect_only = tokens.iter().any(|t| t == "--connect-only");
        let address = match format!("{}:{}", tokens[1], tokens[2]).parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                return CommandValue::failed(format!(
                    "invalid border-agent address '{}:{}'",
                    tokens[1], tokens[2]
                ));
            }
        };
        let config = match self.config.to_commissioner_config() {
            Ok(config) => config,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        let (commissioner, events) = match Commissioner::connect_only(config, address).await {
            Ok(session) => session,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        if let Err(err) = self.install_joiner_handler(&commissioner) {
            return CommandValue::failed(err.to_string());
        }
        // Petition unless `--connect-only`. A border agent that accepts the
        // petition echoes our own Commissioner ID back in the response; that is
        // not a conflict, so an accepted petition (`Ok`) is success. Only
        // `Error::PetitionRejected` — returned when a different commissioner is
        // already active — is a failure.
        let petition_result = if connect_only {
            Ok(())
        } else {
            commissioner.petition().await.map(|_| ())
        };
        // Keep the connected session regardless of the petition outcome so the
        // user can inspect `state` and `stop` to disconnect, as the C++ CLI does.
        // Keep-alives run in the session itself once the petition is accepted.
        self.commissioner = Some(commissioner);
        self.events = Some(events);
        petition_result.into()
    }

    pub(super) async fn cmd_stop(&mut self) -> CommandValue {
        self.events = None;
        match self.commissioner.take() {
            Some(commissioner) => commissioner.resign().await.into(),
            None => CommandValue::done(),
        }
    }

    pub(super) fn cmd_config(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let property = tokens[2].as_str();
        if property != "pskc" && property != "admincode" {
            return CommandValue::failed(format!("{property} is not a valid property"));
        }
        match tokens[1].as_str() {
            "get" => {
                if property == "admincode" {
                    CommandValue::ok(self.config.admin_code.to_string())
                } else {
                    CommandValue::ok(hex::encode(self.config.pskc.as_slice()))
                }
            }
            "set" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                if property == "admincode" {
                    self.config.admin_code = Zeroizing::new(tokens[3].clone());
                    self.config.pskc = Zeroizing::new(tokens[3].as_bytes().to_vec());
                    CommandValue::done()
                } else {
                    match hex::decode(tokens[3].trim()) {
                        Ok(bytes) => {
                            self.config.pskc = Zeroizing::new(bytes);
                            CommandValue::done()
                        }
                        Err(err) => CommandValue::failed(format!("invalid PSKc hex: {err}")),
                    }
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }
}
