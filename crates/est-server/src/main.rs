use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use est_server::config::Config;
use est_server::pending::{PendingStore, Status};

/// EST (RFC 7030) server: certificates for small clients, from a local CA
/// or through cert-manager.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Configuration file.
    #[arg(
        short,
        long,
        env = "EST_SERVER_CONFIG",
        default_value = "/etc/est-server/est-server.toml",
        global = true
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve,
    /// Check the configuration and exit.
    CheckConfig,
    /// Create a CA, a server certificate and a configuration for a
    /// standalone server.
    Init {
        /// Directory to create them in.
        #[arg(long)]
        dir: PathBuf,
        /// DNS name of the server (repeatable).
        #[arg(long = "dns-name")]
        dns_names: Vec<String>,
        /// IP address of the server (repeatable, IPv4 or IPv6).
        #[arg(long = "ip")]
        ip_addresses: Vec<IpAddr>,
        /// Common name of the CA.
        #[arg(long, default_value = "EST CA")]
        ca_name: String,
        /// ECDSA P-384 for the CA instead of P-256.
        #[arg(long)]
        p384: bool,
        /// Name pattern that gets certificates without approval (repeatable).
        #[arg(long)]
        allow: Vec<String>,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Requests waiting for approval (local CA).
    #[command(subcommand)]
    Pending(PendingCommand),
}

#[derive(Subcommand)]
enum PendingCommand {
    /// List requests.
    List {
        /// Decided requests too.
        #[arg(long)]
        all: bool,
    },
    /// Show a request with its CSR.
    Show { id: String },
    /// Approve a request; the client gets its certificate when it asks again.
    Approve { id: String },
    /// Deny a request.
    Deny { id: String },
    /// Forget a request.
    Delete { id: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,kube=warn,hyper=warn".into()),
        )
        .init();
    match cli.command {
        Command::Serve => serve(&cli.config),
        Command::CheckConfig => {
            Config::load(&cli.config)?;
            println!("{}: ok", cli.config.display());
            Ok(())
        }
        Command::Init {
            dir,
            dns_names,
            ip_addresses,
            ca_name,
            p384,
            allow,
            force,
        } => est_server::init::run(&est_server::init::InitOptions {
            dir,
            ca_name,
            p384,
            dns_names,
            ip_addresses,
            allow,
            force,
        }),
        Command::Pending(cmd) => pending(&cli.config, cmd),
    }
}

fn serve(config_path: &Path) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let running = est_server::app::start(&config).await?;
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = running.wait() => anyhow::bail!("a listener stopped"),
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        tracing::info!("shutting down");
        Ok(())
    })
}

fn pending(config_path: &Path, cmd: PendingCommand) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let store = PendingStore::open(&config.server.state_dir)
        .with_context(|| format!("state directory {}", config.server.state_dir.display()))?;
    match cmd {
        PendingCommand::List { all } => {
            let entries: Vec<_> = store
                .list()?
                .into_iter()
                .filter(|e| all || e.status == Status::Pending)
                .collect();
            if entries.is_empty() {
                println!("no {}requests", if all { "" } else { "pending " });
            }
            for e in entries {
                println!(
                    "{}  {:<8}  {:<10}  {}  from {}{}",
                    e.id,
                    format!("{:?}", e.status).to_lowercase(),
                    if e.label.is_empty() {
                        "(default)"
                    } else {
                        &e.label
                    },
                    e.names.join(","),
                    e.client,
                    e.client_cert.map(|c| format!(" [{c}]")).unwrap_or_default(),
                );
            }
        }
        PendingCommand::Show { id } => {
            let e = store.find(&id)?;
            println!("{}", serde_json::to_string_pretty(&e)?);
        }
        PendingCommand::Approve { id } => {
            let e = store.decide(&id, true)?;
            println!("approved {} for {}", e.id, e.names.join(","));
        }
        PendingCommand::Deny { id } => {
            let e = store.decide(&id, false)?;
            println!("denied {} for {}", e.id, e.names.join(","));
        }
        PendingCommand::Delete { id } => {
            let e = store.find(&id)?;
            store.remove(&e.id)?;
            println!("deleted {}", e.id);
        }
    }
    Ok(())
}
