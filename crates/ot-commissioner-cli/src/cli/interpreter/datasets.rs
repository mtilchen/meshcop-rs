use super::*;

impl Interpreter {
    // --- datasets ---

    pub(super) async fn cmd_comm_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "get" => match commissioner
                .get_commissioner_dataset(CommissionerDatasetFlags::ALL)
                .await
            {
                Ok(dataset) => CommandValue::ok(json::dump(&json::comm_dataset_to_json(&dataset))),
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "set" => {
                if tokens.len() < 3 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                match serde_json::from_str(&tokens[2])
                    .map_err(|e| e.to_string())
                    .and_then(|v| json::comm_dataset_from_json(&v).map_err(|e| e.to_string()))
                {
                    Ok(dataset) => commissioner.set_commissioner_dataset(&dataset).await.into(),
                    Err(message) => CommandValue::failed(message),
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    pub(super) async fn cmd_bbr_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "get" => match commissioner
                .get_bbr_dataset(CommissionerDatasetFlags::ALL)
                .await
            {
                Ok(dataset) => {
                    let map: serde_json::Map<String, serde_json::Value> = dataset
                        .entries()
                        .iter()
                        .map(|e| (format!("Tlv{}", e.ty), json!(hex::encode(&e.value))))
                        .collect();
                    CommandValue::ok(json::dump(&serde_json::Value::Object(map)))
                }
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "set" => CommandValue::failed(
                "bbrdataset set requires typed BBR TLVs not yet modeled in this build",
            ),
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    pub(super) async fn cmd_op_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let is_set = match tokens[1].as_str() {
            "get" => false,
            "set" => true,
            other => return CommandValue::failed(format!("{other} is not a valid sub-command")),
        };
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        let field = tokens[2].as_str();

        // Full active/pending dataset JSON.
        if field == "active" || field == "pending" {
            let pending = field == "pending";
            if is_set {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let dataset = match serde_json::from_str(&tokens[3])
                    .map_err(|e| e.to_string())
                    .and_then(|v| {
                        json::op_dataset_from_json(&v, pending).map_err(|e| e.to_string())
                    }) {
                    Ok(dataset) => dataset,
                    Err(message) => return CommandValue::failed(message),
                };
                return if pending {
                    commissioner.set_pending_dataset(&dataset).await.into()
                } else {
                    commissioner.set_active_dataset(&dataset).await.into()
                };
            }
            let dataset = if pending {
                commissioner.get_pending_dataset(DatasetFlags::ALL).await
            } else {
                commissioner.get_active_dataset(DatasetFlags::ALL).await
            };
            return match dataset {
                Ok(dataset) => match json::op_dataset_to_json(&dataset, pending) {
                    Ok(value) => CommandValue::ok(json::dump(&value)),
                    Err(err) => CommandValue::failed(err.to_string()),
                },
                Err(err) => CommandValue::failed(err.to_string()),
            };
        }

        // Per-field get/set: the get reads the active dataset and projects one
        // field; the set issues an active/pending dataset update.
        if is_set {
            self.op_dataset_field_set(field, tokens).await
        } else {
            self.op_dataset_field_get(field).await
        }
    }

    async fn op_dataset_field_get(&mut self, field: &str) -> CommandValue {
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        let dataset = match commissioner.get_active_dataset(DatasetFlags::ALL).await {
            Ok(dataset) => dataset,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        let result = (|| -> meshcop::Result<Option<String>> {
            Ok(match field {
                "activetimestamp" => dataset
                    .active_timestamp()?
                    .map(|ts| json::dump(&json::timestamp_json(ts))),
                "channel" => dataset
                    .channel()?
                    .map(|c| json::dump(&json::channel_json(c))),
                "channelmask" => dataset
                    .channel_mask()?
                    .map(|m| json::dump(&json::channel_mask_json(&m))),
                "xpanid" => dataset.extended_pan_id()?.map(hex::encode),
                "meshlocalprefix" => dataset
                    .mesh_local_prefix()?
                    .map(json::mesh_local_prefix_string),
                "networkmasterkey" => dataset.network_key()?.map(hex::encode),
                "networkname" => dataset.network_name()?.map(str::to_string),
                "panid" => dataset.pan_id()?.map(|p| format!("0x{p:04x}")),
                "pskc" => dataset.pskc().map(hex::encode),
                "securitypolicy" => dataset
                    .security_policy()?
                    .map(|p| json::dump(&json::security_policy_json(p))),
                _ => return Ok(None),
            })
        })();
        match result {
            Ok(Some(value)) => CommandValue::ok(value),
            Ok(None) => {
                if is_known_op_field(field) {
                    CommandValue::failed(format!("{field} is not present in the active dataset"))
                } else {
                    CommandValue::failed(format!("{field} is not a valid property"))
                }
            }
            Err(err) => CommandValue::failed(err.to_string()),
        }
    }

    async fn op_dataset_field_set(&mut self, field: &str, tokens: &Tokens) -> CommandValue {
        // Build a minimal dataset carrying the one field (plus delay where the
        // C++ syntax includes it) and issue an active-dataset update.
        let mut dataset = Dataset::default();
        let set_result: std::result::Result<bool, String> = (|| {
            match field {
                "channel" => {
                    let page = parse_u64(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .ok_or("invalid page")?;
                    let number = parse_u64(tokens.get(4).map(String::as_str).unwrap_or(""))
                        .ok_or("invalid channel")?;
                    dataset.set_raw(
                        meshcop::dataset::TLV_CHANNEL,
                        meshcop::dataset::Channel {
                            page: page as u8,
                            channel: number as u16,
                        }
                        .to_value()
                        .to_vec(),
                    );
                }
                "xpanid" => dataset.set_raw(
                    meshcop::dataset::TLV_EXTENDED_PAN_ID,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "networkmasterkey" => dataset.set_raw(
                    meshcop::dataset::TLV_NETWORK_KEY,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "networkname" => dataset.set_raw(
                    meshcop::dataset::TLV_NETWORK_NAME,
                    tokens
                        .get(3)
                        .map(String::as_str)
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec(),
                ),
                "panid" => {
                    let panid = json::parse_panid(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .map_err(|e| e.to_string())?;
                    dataset.set_raw(meshcop::dataset::TLV_PAN_ID, panid.to_be_bytes().to_vec());
                }
                "pskc" => dataset.set_raw(
                    meshcop::dataset::TLV_PSKC,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "meshlocalprefix" => dataset.set_raw(
                    meshcop::dataset::TLV_MESH_LOCAL_PREFIX,
                    json::parse_mesh_local_prefix(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                ),
                "securitypolicy" => {
                    let rotation = tokens
                        .get(3)
                        .and_then(|t| t.parse::<u16>().ok())
                        .ok_or("invalid rotation time")?;
                    let flag_bytes =
                        hex::decode(tokens.get(4).map(String::as_str).unwrap_or("").trim())
                            .map_err(|e| e.to_string())?;
                    let flags = match flag_bytes.as_slice() {
                        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
                        [only] => u16::from(*only) << 8,
                        [] => return Err("flags must not be empty".to_string()),
                    };
                    dataset.set_raw(
                        meshcop::dataset::TLV_SECURITY_POLICY,
                        meshcop::dataset::SecurityPolicy {
                            rotation_time: rotation,
                            flags: meshcop::dataset::SecurityPolicyFlags::from_bits_retain(flags),
                        }
                        .to_value()
                        .to_vec(),
                    );
                }
                _ => return Ok(false),
            }
            Ok(true)
        })();
        match set_result {
            Ok(true) => {
                let Some(commissioner) = self.commissioner.as_mut() else {
                    return CommandValue::failed(NOT_CONNECTED);
                };
                // MGMT_ACTIVE_SET requires an Active Timestamp TLV newer than
                // the network's. Fetch the current timestamp and bump it, like
                // the C++ CommissionerApp does for per-field setters.
                let seconds = match commissioner
                    .get_active_dataset(DatasetFlags::ACTIVE_TIMESTAMP)
                    .await
                    .and_then(|current| current.active_timestamp())
                {
                    Ok(Some(ts)) => ts.seconds() + 1,
                    Ok(None) => 1,
                    Err(err) => return CommandValue::failed(err.to_string()),
                };
                dataset.set_raw(
                    meshcop::dataset::TLV_ACTIVE_TIMESTAMP,
                    meshcop::dataset::Timestamp::from_components(seconds, 0, false)
                        .to_value()
                        .to_vec(),
                );
                commissioner.set_active_dataset(&dataset).await.into()
            }
            Ok(false) => CommandValue::failed(format!("{field} cannot be set")),
            Err(message) => CommandValue::failed(message),
        }
    }
}
