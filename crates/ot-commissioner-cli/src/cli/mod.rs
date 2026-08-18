//! The `ot-commissioner-rs` command-line REPL.
//!
//! This module reimplements the interactive command surface, prompt, colored
//! `[done]`/`[failed]` output, startup logo, and usage banner of the C++
//! `ot-commissioner` CLI on top of Mesh Five-O's
//! [`mesh50::commissioner`] API. It is driven by the
//! `ot-commissioner-rs` binary (`src/main.rs`).
//!
//! Commands that exercise the non-CCM commissioner protocol are fully wired to
//! the library. Commands outside that scope (CCM token flows, the persistent
//! network registry, mDNS discovery, and multi-network job execution) keep
//! their exact usage text but report `[failed]` with an explanatory message.

mod config;
mod console;
mod interpreter;
mod json;
mod value;

use std::path::Path;

use zeroize::Zeroizing;

use console::Color;
use interpreter::Interpreter;

/// The startup logo: the C++ CLI banner (font "Slant") re-rendered with the
/// text "OT-commissioner-rs CLI", with Ferris (from `ferris-says`) perched
/// under the "-rs". Printed in blue like the reference.
const LOGO: &str = concat!(
    r"   ____  ______                                   _           _                                          ________    ____",
    "\n",
    r"  / __ \/_  __/   _________  ____ ___  ____ ___  (_)_________(_)___  ____  ___  _____      __________   / ____/ /   /  _/",
    "\n",
    r" / / / / / /_____/ ___/ __ \/ __ `__ \/ __ `__ \/ / ___/ ___/ / __ \/ __ \/ _ \/ ___/_____/ ___/ ___/  / /   / /    / /",
    "\n",
    r"/ /_/ / / /_____/ /__/ /_/ / / / / / / / / / / / (__  |__  ) / /_/ / / / /  __/ /  /_____/ /  (__  )  / /___/ /____/ /",
    "\n",
    r"\____/ /_/      \___/\____/_/ /_/ /_/_/ /_/ /_/_/____/____/_/\____/_/ /_/\___/_/        /_/  /____/   \____/_____/___/",
    "\n",
    r"                                                                                         _~^~^~_",
    "\n",
    r"                                                                                     \) /  o o  \ (/",
    "\n",
    r"                                                                                       '_   -   _'",
    "\n",
    r"                                                                                       \ '-----' /",
    "\n",
);

/// Prints the startup logo in blue, matching the C++ CLI.
pub fn print_logo() {
    console::write(LOGO, Color::Blue);
}

/// Prints the crate version, matching `ot-commissioner -v`.
pub fn print_version() {
    console::write(env!("CARGO_PKG_VERSION"), Color::White);
}

/// Builds the usage banner for `program`, matching the C++ `PrintUsage` text.
fn usage_text(program: &str) -> String {
    format!(
        "usage: \n\
         help digest:\n    {program} -h|--help\n\
         version:\n    {program} -v|--version\n\
         common options\n    {program} [-r|--registry <registryFileName>] [-c|--config <configFileName>]\n\
         or\n    {program} [-r|--registry <registryFileName>] [configFileName]"
    )
}

/// Prints the usage banner for `program`, matching the C++ `PrintUsage`.
pub fn print_usage(program: &str) {
    console::write(&usage_text(program), Color::White);
}

/// A parsed command-line invocation of the `ot-commissioner-rs` binary.
#[derive(Debug, PartialEq, Eq)]
pub enum CliInvocation {
    /// `-h`/`--help`: print the usage banner and exit successfully.
    Usage,
    /// `-v`/`--version`: print the version and exit successfully.
    Version,
    /// Malformed arguments: print the usage banner and exit with failure.
    UsageError,
    /// Run the REPL, optionally loading the given configuration file.
    Run(Option<std::path::PathBuf>),
}

/// Parses the binary's arguments (everything after the program name) the way
/// the C++ entry point does: `-h`/`-v` win immediately, an explicit
/// `-c`/`--config` wins over the `[configFileName]` positional form, and
/// `-r`/`--registry` is accepted for parity but ignored (the persistent
/// network registry is out of scope for this build).
pub fn parse_invocation(args: &[String]) -> CliInvocation {
    let mut config_path: Option<std::path::PathBuf> = None;
    let mut positional: Option<std::path::PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-h" | "--help" => return CliInvocation::Usage,
            "-v" | "--version" => return CliInvocation::Version,
            "-c" | "--config" => match rest.next() {
                Some(path) => config_path = Some(std::path::PathBuf::from(path)),
                None => return CliInvocation::UsageError,
            },
            "-r" | "--registry" => {
                if rest.next().is_none() {
                    return CliInvocation::UsageError;
                }
            }
            other => {
                // The first non-option argument is the config file, matching
                // the C++ `[configFileName]` positional form.
                if !other.starts_with('-') && positional.is_none() {
                    positional = Some(std::path::PathBuf::from(other));
                }
            }
        }
    }
    CliInvocation::Run(config_path.or(positional))
}

/// Loads the configuration (defaulting to non-CCM with an unset PSKc when no
/// file is given, as the C++ CLI does) and runs the REPL until `exit`/`quit`
/// or end-of-input. On a configuration-load failure it prints the C++-style
/// startup error and returns it.
pub async fn run(config_path: Option<&Path>) -> mesh50::Result<()> {
    let config = match config_path {
        Some(path) => match config::CliConfig::load(path) {
            Ok(config) => config,
            Err(err) => {
                console::write(
                    &format!("start OT-commissioner CLI failed: {err}"),
                    Color::Red,
                );
                return Err(err);
            }
        },
        None => config::CliConfig::default(),
    };

    let mut interpreter = Interpreter::new(config);
    while !interpreter.should_exit() {
        // Keep one blocking stdin read alive while the async side services the
        // absolute commissioner keep-alive deadline. Reusing the same task
        // after a timer tick avoids starting multiple readers for stdin.
        let mut input = tokio::task::spawn_blocking(console::read);
        loop {
            let input_result = match interpreter.keepalive_deadline() {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        () = tokio::time::sleep_until(deadline) => {
                            if let Err(err) = interpreter.handle_scheduled_keepalive().await {
                                console::write(&format!("keep-alive failed: {err}"), Color::Red);
                            }
                            None
                        },
                        result = &mut input => Some(result),
                    }
                }
                None => Some((&mut input).await),
            };

            let Some(input_result) = input_result else {
                continue;
            };
            match input_result {
                Ok(Some(line)) => {
                    let line = Zeroizing::new(line);
                    interpreter.evaluate_and_print(&line).await;
                }
                Ok(None) | Err(_) => return Ok(()),
            }
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn logo_is_the_slant_banner_with_ferris() {
        assert!(LOGO.contains("_~^~^~_")); // Ferris
        assert!(LOGO.starts_with("   ____  ______"));
    }

    #[test]
    fn usage_text_matches_the_cpp_banner_shape() {
        let usage = usage_text("ot-commissioner-rs");
        assert!(usage.starts_with("usage: \n"));
        assert!(usage.contains("ot-commissioner-rs -h|--help"));
        assert!(usage.contains("ot-commissioner-rs -v|--version"));
        assert!(usage.contains("[-r|--registry <registryFileName>] [configFileName]"));
    }

    #[test]
    fn help_and_version_flags_win_immediately() {
        assert_eq!(parse_invocation(&args(&["-h"])), CliInvocation::Usage);
        assert_eq!(parse_invocation(&args(&["--help"])), CliInvocation::Usage);
        assert_eq!(parse_invocation(&args(&["-v"])), CliInvocation::Version);
        assert_eq!(
            parse_invocation(&args(&["--version", "-c", "x"])),
            CliInvocation::Version
        );
    }

    #[test]
    fn config_flag_wins_over_positional_config() {
        assert_eq!(parse_invocation(&[]), CliInvocation::Run(None));
        assert_eq!(
            parse_invocation(&args(&["cfg.json"])),
            CliInvocation::Run(Some(PathBuf::from("cfg.json")))
        );
        assert_eq!(
            parse_invocation(&args(&["positional.json", "-c", "explicit.json"])),
            CliInvocation::Run(Some(PathBuf::from("explicit.json")))
        );
        // Only the first positional is honored; unknown flags are skipped.
        assert_eq!(
            parse_invocation(&args(&["first.json", "second.json", "-x"])),
            CliInvocation::Run(Some(PathBuf::from("first.json")))
        );
    }

    #[test]
    fn registry_flag_is_consumed_and_missing_flag_values_are_errors() {
        assert_eq!(
            parse_invocation(&args(&["-r", "registry.json", "-c", "cfg.json"])),
            CliInvocation::Run(Some(PathBuf::from("cfg.json")))
        );
        assert_eq!(parse_invocation(&args(&["-c"])), CliInvocation::UsageError);
        assert_eq!(
            parse_invocation(&args(&["--registry"])),
            CliInvocation::UsageError
        );
    }
}
