use super::*;

impl Interpreter {
    pub(super) async fn cmd_netdiag(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_ref() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "query" => {
                // netdiag query [extaddr|rloc16] <addr>
                let (flags, addr_token) = if tokens.len() >= 4 {
                    let flags = match tokens[2].as_str() {
                        "extaddr" => diag_flags::EXT_MAC_ADDR,
                        "rloc16" => diag_flags::MAC_ADDR,
                        other => {
                            return CommandValue::failed(format!("{other} is not a valid type"));
                        }
                    };
                    (flags, &tokens[3])
                } else {
                    (DEFAULT_NETDIAG_FLAGS, &tokens[2])
                };
                let Some(dst) = parse_addr(addr_token) else {
                    return CommandValue::failed(format!("invalid address '{addr_token}'"));
                };
                match commissioner.get_diagnostics(dst, flags).await {
                    Ok(data) => CommandValue::ok(json::dump(&net_diag_json(&data))),
                    Err(err) => CommandValue::failed(err.to_string()),
                }
            }
            "reset" => {
                if tokens.len() < 4 || tokens[2] != "maccounters" {
                    return CommandValue::failed(
                        "only 'netdiag reset maccounters <addr>' supported",
                    );
                }
                let Some(dst) = parse_addr(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid address '{}'", tokens[3]));
                };
                commissioner
                    .diagnostic_reset(Some(dst), diag_flags::MAC_COUNTERS)
                    .await
                    .into()
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }
}
