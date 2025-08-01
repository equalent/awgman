use std::path::absolute;

use anyhow::{anyhow, Result};
use awgman::{
    utils::{gen_psk, pause},
    vault::{AWGParams, Device, Protocol, Server},
    vault_file::VaultFile,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use expanduser::expanduser;
use inquire::{
    validator::Validation, CustomUserError, Password, PasswordDisplayMode, Select, Text,
};
use regex::Regex;
use secrecy::SecretString;

use colored::Colorize;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser, Debug)]
#[command(version)]
#[command(about = "WireGuard/AmneziaWG keychain and manager TUI")]
struct Args {
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(long, help = "Disable ASCII logo", default_value_t = false)]
    nologo: bool,

    #[arg(help = "Path to the vault file", default_value = "awgvault.db")]
    vault_path: String,
}

fn validate_password(password: &str) -> Result<Validation, CustomUserError> {
    if password.len() < 12 {
        return Ok(Validation::Invalid(
            "Password must be at least 12 characters long.".into(),
        ));
    }
    if !Regex::new(r"[a-z]").unwrap().is_match(password) {
        return Ok(Validation::Invalid(
            "Password must contain at least one lowercase letter.".into(),
        ));
    }
    if !Regex::new(r"[A-Z]").unwrap().is_match(password) {
        return Ok(Validation::Invalid(
            "Password must contain at least one uppercase letter.".into(),
        ));
    }
    if !Regex::new(r"\d").unwrap().is_match(password) {
        return Ok(Validation::Invalid(
            "Password must contain at least one number.".into(),
        ));
    }
    if !Regex::new(r"[^\w\s]").unwrap().is_match(password) {
        return Ok(Validation::Invalid(
            "Password must contain at least one special character.".into(),
        ));
    }
    if Regex::new(r"\s").unwrap().is_match(password) {
        return Ok(Validation::Invalid(
            "Password must not contain whitespace.".into(),
        ));
    }
    Ok(Validation::Valid)
}

struct Context {
    args: Args,
    vault: VaultFile,
}

fn do_view_devices(ctx: &Context) -> Result<()> {
    let vault = ctx.vault.vault();

    if vault.devices.is_empty() {
        println!("🤷 No devices in the vault");
    } else {
        for device in vault.devices.as_slice() {
            let pubkey = PublicKey::from(&device.secret).to_bytes();

            println!("\n--- {}", device.name);
            println!("    User: {}", device.user);
            println!("    Public Key: {}", BASE64_STANDARD.encode(pubkey));
        }
    }

    //pause();

    Ok(())
}

fn do_add_device(ctx: &mut Context) -> Result<()> {
    let name = match Text::new("Enter DEVICE NAME:").prompt_skippable()? {
        Some(n) => n,
        None => return Ok(()),
    };

    let user = match Text::new("Enter DEVICE USER:").prompt_skippable()? {
        Some(n) => n,
        None => return Ok(()),
    };

    let secret = StaticSecret::random();
    let psk = gen_psk()?;

    println!("Saving...");
    ctx.vault.transact(|v| {
        v.devices.push(Device {
            name,
            user,
            secret,
            psk,
        });
        Ok(())
    })
}

fn do_remove_device(ctx: &mut Context) -> Result<()> {
    let vault = ctx.vault.vault();

    let device = match Select::new(
        "Which device do you want to remove?",
        vault.devices.to_vec(),
    )
    .prompt_skippable()?
    {
        Some(n) => n,
        None => return Ok(()),
    };

    println!("Saving...");
    ctx.vault.transact(|v| {
        v.devices.retain(|d| *d != device);
        Ok(())
    })
}

fn do_generate_device_config(ctx: &Context) -> Result<()> {
    let vault = ctx.vault.vault();

    let device = match Select::new(
        "Select device:",
        vault.devices.to_vec(),
    )
    .prompt_skippable()?
    {
        Some(n) => n,
        None => return Ok(()),
    };

    let server = match Select::new(
        "Select server:",
        vault.servers.to_vec(),
    )
    .prompt_skippable()?
    {
        Some(n) => n,
        None => return Ok(()),
    };

    println!("{}", device.generate_config(&server)?);
    Ok(())
}

fn do_view_servers(ctx: &Context) -> Result<()> {
    let vault = ctx.vault.vault();

    if vault.servers.is_empty() {
        println!("🤷 No servers in the vault");
    } else {
        for server in vault.servers.as_slice() {
            let pubkey = PublicKey::from(&server.secret).to_bytes();

            println!("\n--- {}", server.name);
            println!("    Endpoint: {}", server.endpoint);
            println!("    Public Key: {}", BASE64_STANDARD.encode(pubkey));
        }
    }

    //pause();

    Ok(())
}

fn do_add_server(ctx: &mut Context) -> Result<()> {
    let name = match Text::new("Enter SERVER NAME:").prompt_skippable()? {
        Some(n) => n,
        None => return Ok(()),
    };

    let endpoint = match Text::new("Enter SERVER ENDPOINT:").prompt_skippable()? {
        Some(n) => n,
        None => return Ok(()),
    };

    let protocols = vec!["WireGuard", "AmneziaWG"];
    let protocol = match Select::new("Choose SERVER PROTOCOL:", protocols).prompt_skippable()? {
        Some(p) => match p {
            "WireGuard" => Protocol::WireGuard,
            "AmneziaWG" => Protocol::AmneziaWG(AWGParams::generate()),
            _ => return Ok(())
        },
        None => return Ok(()),
    };

    let secret = StaticSecret::random();

    println!("Saving...");
    ctx.vault.transact(|v| {
        v.servers.push(Server {
            name,
            endpoint,
            protocol,
            secret,
        });
        Ok(())
    })
}

fn do_verify_current_password(ctx: &mut Context) -> Result<()> {
    loop {
        let password = SecretString::from(
            Password::new("Enter CURRENT VAULT PASSWORD:")
                .without_confirmation()
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()?,
        );

        if ctx.vault.is_password_correct(password) {
            return Ok(());
        }

        println!("❌ Incorrect password! Please try again...");
    }
}

fn do_change_password(ctx: &mut Context) -> Result<()> {
    do_verify_current_password(ctx)?;

    let new_password = SecretString::from(
        Password::new("Enter password:")
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_validator(validate_password)
            .prompt_skippable()?
            .ok_or_else(|| anyhow!("Password change cancelled"))?,
    );

    ctx.vault.update_password(new_password)?;

    println!("✅ Password changed successfully!");
    Ok(())
}

fn do_top(ctx: &mut Context) -> Result<()> {
    let options: Vec<&str> = vec![
        "View devices",
        "Add device",
        "Remove device",
        "Generate device config",
        "View servers",
        "Add server",
        "Remove server",
        "Generate server config",
        "Change password",
        "[DEBUG] Force save",
        "Exit",
    ];

    let ans = Select::new("What do you want to do?", options).prompt();

    match ans {
        Ok(v) => match v {
            "View devices" => do_view_devices(ctx),
            "Add device" => do_add_device(ctx),
            "Remove device" => do_remove_device(ctx),
            "Generate device config" => do_generate_device_config(ctx),
            "View servers" => do_view_servers(ctx),
            "Add server" => do_add_server(ctx),
            "Change password" => do_change_password(ctx),
            "Exit" => Err(anyhow!("Exit!")),
            "[DEBUG] Force save" => ctx.vault.save(),
            _ => Ok(()),
        },
        Err(e) => Err(e.into()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let vault_path = expanduser(&args.vault_path)?;

    let vault: VaultFile;

    if !args.nologo {
        let ascii = include_str!("ascii.txt");
        println!("\r\n{}\r\n", ascii.bold());
    }

    if vault_path.is_file() {
        println!("Opening existing vault...");
        println!(
            "This vault will be unlocked: {}",
            absolute(&vault_path)?.display()
        );
        println!("\n{}", "(tip: use ESC to cancel)".dimmed().italic());

        loop {
            let password = SecretString::from(
                Password::new("Vault Password:")
                    .without_confirmation()
                    .with_display_toggle_enabled()
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .prompt()?,
            );
            let result = VaultFile::open(&vault_path, &password);
            if result.is_err() {
                println!("Incorrect password! Please try again");
            } else {
                vault = result.unwrap();
                break;
            }
        }
    } else {
        println!("Creating a new vault...");
        println!(
            "Vault will be created here: {}",
            absolute(&vault_path)?.display()
        );
        println!(
            "\n{}",
            "(tip: use Ctrl+R to reveal password)".dimmed().italic()
        );
        println!("{}", "(tip: use ESC to cancel)".dimmed().italic());

        let password = SecretString::from(
            Password::new("Enter password:")
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_validator(validate_password)
                .prompt_skippable()?
                .ok_or_else(|| anyhow!("Vault creation cancelled"))?,
        );
        vault = VaultFile::create(&vault_path, &password)?;
    }

    let mut ctx = Context { args, vault };

    loop {
        do_top(&mut ctx)?;
    }
}
