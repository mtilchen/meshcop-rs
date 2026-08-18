pub fn show_secrets_requested(args: &mut Vec<String>) -> bool {
    let show = args.iter().any(|arg| arg == "--show-secrets");
    args.retain(|arg| arg != "--show-secrets");
    show || std::env::var_os("MESH50_SHOW_SECRETS").is_some()
}
