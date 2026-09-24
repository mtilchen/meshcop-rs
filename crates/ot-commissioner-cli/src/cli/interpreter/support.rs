use super::*;

#[derive(PartialEq, Eq, Clone, Copy)]
pub(super) enum ManagedCommand {
    Reenroll,
    DomainReset,
    Migrate,
}

pub(super) const DEFAULT_NETDIAG_FLAGS: u64 = diag_flags::EXT_MAC_ADDR
    | diag_flags::MAC_ADDR
    | diag_flags::MODE
    | diag_flags::CONNECTIVITY
    | diag_flags::ROUTE64
    | diag_flags::LEADER_DATA;

pub(super) fn is_known_op_field(field: &str) -> bool {
    matches!(
        field,
        "activetimestamp"
            | "channel"
            | "channelmask"
            | "xpanid"
            | "meshlocalprefix"
            | "networkmasterkey"
            | "networkname"
            | "panid"
            | "pskc"
            | "securitypolicy"
    )
}

/// Renders a [`NetDiagData`] answer as a compact JSON object.
pub(super) fn net_diag_json(data: &NetDiagData) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(ext) = &data.ext_mac_addr {
        map.insert("ExtAddress".into(), json!(hex::encode(ext)));
    }
    if let Some(rloc) = data.mac_addr {
        map.insert("Rloc16".into(), json!(format!("0x{rloc:04x}")));
    }
    if let Some(leader) = &data.leader_data {
        map.insert(
            "LeaderData".into(),
            json!({ "PartitionId": leader.partition_id, "LeaderRouterId": leader.router_id }),
        );
    }
    if let Some(route) = &data.route64 {
        map.insert("Route64Routers".into(), json!(route.route_data.len()));
    }
    if let Some(addrs) = &data.addresses {
        map.insert(
            "Addresses".into(),
            json!(addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>()),
        );
    }
    serde_json::Value::Object(map)
}

pub(super) fn parse_addr(s: &str) -> Option<Ipv6Addr> {
    s.trim().parse().ok()
}

pub(super) fn parse_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

pub(super) fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

pub(super) fn has_multi_network_flag(tokens: &Tokens) -> bool {
    tokens.iter().any(|t| t == "--nwk" || t == "--dom")
}
/// Splits a command line into tokens, honoring single/double-quoted spans
/// (used for JSON dataset arguments).
pub(super) fn tokenize(line: &str) -> std::result::Result<Tokens, String> {
    let mut tokens = Zeroizing::new(Vec::new());
    let mut current = Zeroizing::new(String::new());
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    in_token = true;
                } else if ch.is_whitespace() {
                    if in_token {
                        tokens.push(std::mem::take(&mut *current));
                        in_token = false;
                    }
                } else {
                    current.push(ch);
                    in_token = true;
                }
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted argument".to_string());
    }
    if in_token {
        tokens.push(std::mem::take(&mut *current));
    }
    Ok(std::mem::take(&mut *tokens))
}

/// The command table: name plus the verbatim C++ usage string, used by `help`.
pub(super) const COMMANDS: &[(&str, &str)] = &[
    (
        "config",
        "config get admincode\nconfig set admincode <9-digits-thread-administrator-passcode>\nconfig get pskc\nconfig set pskc <pskc-hex-string>",
    ),
    (
        "start",
        "start <border-agent-addr> <border-agent-port> [--connect-only]\nstart [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "stop",
        "stop\nstop [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "active",
        "active\nactive [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "token",
        "token request <registrar-addr> <registrar-port>\ntoken print\ntoken set <signed-token-hex-string-file>",
    ),
    (
        "br",
        "br list [--nwk <network-alias-list> | --dom <domain-name>]\nbr add <json-file-path>\nbr delete (<br-record-id> | --nwk <network-alias-list> | --dom <domain-name>)\nbr scan [--nwk <network-alias-list> | --dom <domain-name>] [--export <json-file-path>] [--timeout <ms>] [--netif <network-interface>]",
    ),
    ("domain", "domain list [--dom <domain-name>]"),
    (
        "network",
        "network save <network-data-file>\nnetwork sync\nnetwork list [--nwk <network-alias-list> | --dom <domain-name>]\nnetwork select <extended-pan-id>|<name>|<pan-id>|none\nnetwork identify",
    ),
    ("sessionid", "sessionid"),
    (
        "borderagent",
        "borderagent discover [<timeout-in-milliseconds>]\nborderagent get locator",
    ),
    (
        "joiner",
        "joiner enable (meshcop|ae|nmkp) <joiner-eui64> [<joiner-password>] [<provisioning-url>]\njoiner enableall (meshcop|ae|nmkp) [<joiner-password>] [<provisioning-url>]\njoiner disable (meshcop|ae|nmkp) <joiner-eui64>\njoiner disableall (meshcop|ae|nmkp)\njoiner getport (meshcop|ae|nmkp)\njoiner setport (meshcop|ae|nmkp) <joiner-udp-port>",
    ),
    (
        "commdataset",
        "commdataset get\ncommdataset set '<commissioner-dataset-in-json-string>'",
    ),
    (
        "opdataset",
        "opdataset get activetimestamp\nopdataset get channel\nopdataset set channel <page> <channel> <delay-in-milliseconds>\nopdataset get channelmask\nopdataset set channelmask (<page> <channel-mask>)...\nopdataset get xpanid\nopdataset set xpanid <extended-pan-id>\nopdataset get meshlocalprefix\nopdataset set meshlocalprefix <prefix> <delay-in-milliseconds>\nopdataset get networkmasterkey\nopdataset set networkmasterkey <network-master-key> <delay-in-milliseconds>\nopdataset get networkname\nopdataset set networkname <network-name>\nopdataset get panid\nopdataset set panid <panid> <delay-in-milliseconds>\nopdataset get pskc\nopdataset set pskc <PSKc>\nopdataset get securitypolicy\nopdataset set securitypolicy <rotation-timer> <flags-hex>\nopdataset get active\nopdataset set active '<active-dataset-in-json-string>'\nopdataset get pending\nopdataset set pending '<pending-dataset-in-json-string>'",
    ),
    (
        "bbrdataset",
        "bbrdataset get trihostname\nbbrdataset set trihostname <TRI-hostname>\nbbrdataset get reghostname\nbbrdataset set reghostname <registrar-hostname>\nbbrdataset get regaddr\nbbrdataset get\nbbrdataset set '<bbr-dataset-in-json-string>'",
    ),
    ("reenroll", "reenroll <device-addr>"),
    ("domainreset", "domainreset <device-addr>"),
    ("migrate", "migrate <device-addr> <designated-network-name>"),
    ("mlr", "mlr (<multicast-addr>)+ <timeout-in-seconds>"),
    (
        "announce",
        "announce <channel-mask> <count> <period> <dst-addr>",
    ),
    (
        "panid",
        "panid query <channel-mask> <panid> <dst-addr>\npanid conflict <panid>",
    ),
    (
        "energy",
        "energy scan <channel-mask> <count> <period> <scan-duration> <dst-addr>\nenergy report [<dst-addr>]",
    ),
    (
        "netdiag",
        "netdiag query [extaddr | rloc16] <dest mesh local address>\nnetdiag reset maccounters <dest mesh local address>",
    ),
    ("state", "state"),
    ("exit", "exit"),
    ("quit", "quit\n(an alias to 'exit' command)"),
    ("help", "help [<command>]"),
];
