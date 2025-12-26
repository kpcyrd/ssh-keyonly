mod args;
mod errors;

use crate::args::Args;
use crate::errors::*;
use clap::Parser;
use env_logger::Env;
use russh::{
    MethodKind, Preferred,
    client::{self, KeyboardInteractiveAuthResponse},
    keys::ssh_key,
};
use std::borrow::Cow;
use std::time::Duration;

struct Client {}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (0, 0) => "warn,ssh_keyonly=info",
        (1, 0) => "warn",
        (_, 0) => "error",
        (_, 1) => "info,ssh_keyonly=debug",
        (_, 2) => "debug",
        (_, 3) => "debug,ssh_keyonly=trace",
        _ => "trace",
    };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level)).init();

    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(25)),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            ]),
            ..Default::default()
        },
        ..<_>::default()
    }
    .into();
    let sh = Client {};

    let mut session = client::connect(config, args.addr, sh).await?;

    let remaining_methods = match session
        .authenticate_keyboard_interactive_start(&args.user, None)
        .await?
    {
        KeyboardInteractiveAuthResponse::Success => {
            bail!(
                "Server has granted access based on our KeyboardInteractive request with no password"
            );
            // we can't probe further because the session is already authenticated
        }
        KeyboardInteractiveAuthResponse::Failure {
            remaining_methods, ..
        } => {
            debug!("KeyboardInteractive request success correctly denied");
            remaining_methods
        }
        KeyboardInteractiveAuthResponse::InfoRequest {
            name,
            instructions,
            prompts,
        } => {
            bail!(
                "Server has accepted our KeyboardInteractive auth request (name={name:?}, instructions={instructions:?}, prompts={prompts:?})"
            );
            // not sure we can probe further, but the server doesn't seem to be key-only
        }
    };

    debug!("Server indicated remaining_methods: {remaining_methods:?}");

    let mut findings = false;
    for method in remaining_methods.iter() {
        match method {
            MethodKind::None => {
                error!("Server is indicating anonymous access support");
                findings = true;
            }
            MethodKind::Password => {
                error!("Server is indicating password auth support");
                findings = true;
            }
            MethodKind::PublicKey => {
                debug!("Server is indicating public key auth support");
            }
            MethodKind::HostBased => {
                error!("Server is indicating password auth support");
                findings = true;
            }
            MethodKind::KeyboardInteractive => {
                error!("Server is indicating KeyboardInteractive auth support");
                findings = true;
            }
        }
    }

    if findings {
        bail!("Server has unexpected authentication methods")
    } else {
        info!("Server doesn't indicate support authentication beyond public key auth");
        Ok(())
    }
}
