use super::*;

impl Interpreter {
    // --- managed-device commands ---

    pub(super) async fn cmd_managed(
        &mut self,
        tokens: &Tokens,
        command: ManagedCommand,
    ) -> CommandValue {
        let needed = if command == ManagedCommand::Migrate {
            3
        } else {
            2
        };
        if tokens.len() < needed {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(dst) = parse_addr(&tokens[1]) else {
            return CommandValue::failed(format!("invalid device address '{}'", tokens[1]));
        };
        let Some(commissioner) = self.commissioner.as_ref() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match command {
            ManagedCommand::Reenroll => commissioner.command_reenroll(dst).await.into(),
            ManagedCommand::DomainReset => commissioner.command_domain_reset(dst).await.into(),
            ManagedCommand::Migrate => commissioner.command_migrate(dst, &tokens[2]).await.into(),
        }
    }

    pub(super) async fn cmd_mlr(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let timeout = match tokens[tokens.len() - 1].parse::<u32>() {
            Ok(t) => t,
            Err(_) => return CommandValue::failed("invalid timeout"),
        };
        let addresses: Vec<String> = tokens[1..tokens.len() - 1].to_vec();
        let Some(commissioner) = self.commissioner.as_ref() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match commissioner
            .register_multicast_listener(&addresses, timeout)
            .await
        {
            Ok(status) => CommandValue::ok(status.to_string()),
            Err(err) => CommandValue::failed(err.to_string()),
        }
    }

    pub(super) async fn cmd_announce(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 5 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let (Some(mask), Some(count), Some(period), Some(dst)) = (
            parse_u32(&tokens[1]),
            tokens[2].parse::<u8>().ok(),
            tokens[3].parse::<u16>().ok(),
            parse_addr(&tokens[4]),
        ) else {
            return CommandValue::failed("invalid announce arguments");
        };
        let Some(commissioner) = self.commissioner.as_ref() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        commissioner
            .announce_begin(mask, count, period, dst)
            .await
            .into()
    }

    pub(super) async fn cmd_panid(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "query" => {
                if tokens.len() < 5 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let (Some(mask), Some(panid), Some(dst)) = (
                    parse_u32(&tokens[2]),
                    json::parse_panid(&tokens[3]).ok(),
                    parse_addr(&tokens[4]),
                ) else {
                    return CommandValue::failed("invalid panid query arguments");
                };
                {
                    let Some(commissioner) = self.commissioner.as_ref() else {
                        return CommandValue::failed(NOT_CONNECTED);
                    };
                    if let Err(err) = commissioner.pan_id_query(mask, panid, dst).await {
                        return CommandValue::failed(err.to_string());
                    }
                }
                self.pump_events(Duration::from_secs(3)).await
            }
            "conflict" => {
                if tokens.len() < 3 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(panid) = json::parse_panid(&tokens[2]).ok() else {
                    return CommandValue::failed("invalid panid");
                };
                let reports: Vec<_> = self
                    .panid_conflicts
                    .iter()
                    .filter(|(_, _, p)| *p == panid)
                    .map(|(peer, mask, p)| {
                        json!({ "Peer": peer, "ChannelMask": format!("0x{mask:08x}"), "PanId": format!("0x{p:04x}") })
                    })
                    .collect();
                CommandValue::ok(json::dump(&serde_json::Value::Array(reports)))
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    pub(super) async fn cmd_energy(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "scan" => {
                if tokens.len() < 7 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let (Some(mask), Some(count), Some(period), Some(duration), Some(dst)) = (
                    parse_u32(&tokens[2]),
                    tokens[3].parse::<u8>().ok(),
                    tokens[4].parse::<u16>().ok(),
                    tokens[5].parse::<u16>().ok(),
                    parse_addr(&tokens[6]),
                ) else {
                    return CommandValue::failed("invalid energy scan arguments");
                };
                {
                    let Some(commissioner) = self.commissioner.as_ref() else {
                        return CommandValue::failed(NOT_CONNECTED);
                    };
                    if let Err(err) = commissioner
                        .energy_scan(mask, count, period, duration, dst)
                        .await
                    {
                        return CommandValue::failed(err.to_string());
                    }
                }
                self.pump_events(Duration::from_secs(3)).await
            }
            "report" => {
                let filter = tokens
                    .get(2)
                    .and_then(|t| parse_addr(t))
                    .map(|a| a.to_string());
                let reports: Vec<_> = self
                    .energy_reports
                    .iter()
                    .filter(|(peer, _, _)| filter.as_ref().is_none_or(|f| f == peer))
                    .map(|(peer, mask, list)| {
                        json!({
                            "Peer": peer,
                            "ChannelMask": format!("0x{mask:08x}"),
                            "EnergyList": list.iter().map(|b| *b as i8 as i64).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                CommandValue::ok(json::dump(&serde_json::Value::Array(reports)))
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }
}
