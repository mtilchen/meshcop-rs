use super::*;

impl Interpreter {
    // --- border agent / joiner ---

    pub(super) async fn cmd_border_agent(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "discover" => {
                CommandValue::failed("mDNS border-agent discovery is not implemented in this build")
            }
            "get" => {
                if tokens.len() < 3 || tokens[2] != "locator" {
                    return CommandValue::failed("only 'borderagent get locator' is supported");
                }
                let Some(commissioner) = self.commissioner.as_mut() else {
                    return CommandValue::failed(NOT_CONNECTED);
                };
                match commissioner
                    .get_commissioner_dataset(CommissionerDatasetFlags::BORDER_AGENT_LOCATOR)
                    .await
                {
                    Ok(dataset) => match dataset.raw(mesh50::meshcop::TLV_BORDER_AGENT_LOCATOR) {
                        Some([hi, lo]) => {
                            CommandValue::ok(format!("0x{:04x}", u16::from_be_bytes([*hi, *lo])))
                        }
                        _ => CommandValue::failed("border agent locator not present"),
                    },
                    Err(err) => CommandValue::failed(err.to_string()),
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    pub(super) async fn cmd_joiner(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let subcommand = tokens[1].as_str();
        let joiner_type = tokens[2].as_str();
        if joiner_type == "ae" || joiner_type == "nmkp" {
            return CommandValue::failed(format!(
                "joiner type '{joiner_type}' (CCM) is not implemented in this build"
            ));
        }
        if joiner_type != "meshcop" {
            return CommandValue::failed(format!("{joiner_type} is not a valid joiner type"));
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match subcommand {
            "enable" => {
                if tokens.len() < 5 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(eui64) = parse_u64(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid EUI-64 '{}'", tokens[3]));
                };
                let pskd = tokens[4].clone();
                let joiner_id = compute_joiner_id(eui64);
                if let Err(err) = commissioner.enable_joiner(&joiner_id).await {
                    return CommandValue::failed(err.to_string());
                }
                self.joiner_pskds.insert(joiner_id, Zeroizing::new(pskd));
                self.reinstall_joiner_handler();
                CommandValue::done()
            }
            "enableall" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                if let Err(err) = commissioner.enable_all_joiners(true).await {
                    return CommandValue::failed(err.to_string());
                }
                self.joiner_all_pskd = Some(Zeroizing::new(tokens[3].clone()));
                self.reinstall_joiner_handler();
                CommandValue::done()
            }
            "disable" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(eui64) = parse_u64(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid EUI-64 '{}'", tokens[3]));
                };
                self.joiner_pskds.remove(&compute_joiner_id(eui64));
                self.reinstall_joiner_handler();
                // Steering is rewritten from the remaining enabled joiners.
                CommandValue::done()
            }
            "disableall" => {
                let result = commissioner.enable_all_joiners(false).await;
                self.joiner_pskds.clear();
                self.joiner_all_pskd = None;
                self.reinstall_joiner_handler();
                result.into()
            }
            "getport" => match commissioner
                .get_commissioner_dataset(CommissionerDatasetFlags::JOINER_UDP_PORT)
                .await
            {
                Ok(dataset) => match dataset.raw(mesh50::meshcop::TLV_JOINER_UDP_PORT) {
                    Some([hi, lo]) => CommandValue::ok(u16::from_be_bytes([*hi, *lo]).to_string()),
                    _ => CommandValue::failed("joiner UDP port not present"),
                },
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "setport" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(port) = tokens[3].parse::<u16>().ok() else {
                    return CommandValue::failed(format!("invalid port '{}'", tokens[3]));
                };
                let mut dataset = Dataset::default();
                dataset.set_raw(
                    mesh50::meshcop::TLV_JOINER_UDP_PORT,
                    port.to_be_bytes().to_vec(),
                );
                commissioner.set_commissioner_dataset(&dataset).await.into()
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    pub(super) fn install_joiner_handler(&mut self, commissioner: &mut Commissioner) {
        let handler = self.build_joiner_handler();
        commissioner.set_joiner_handler(handler);
    }

    fn reinstall_joiner_handler(&mut self) {
        let handler = self.build_joiner_handler();
        if let Some(commissioner) = self.commissioner.as_mut() {
            commissioner.set_joiner_handler(handler);
        }
    }

    pub(super) fn build_joiner_handler(&self) -> StaticJoinerHandler {
        let mut handler = StaticJoinerHandler::new();
        if let Some(pskd) = &self.joiner_all_pskd {
            handler.enable_all(pskd.as_str().to_owned());
        }
        for (id, pskd) in &self.joiner_pskds {
            handler.enable_joiner_id(*id, pskd.as_str().to_owned());
        }
        handler
    }
}
