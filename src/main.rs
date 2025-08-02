use std::fs::OpenOptions;
use std::path::absolute;

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use awgman::{
    vault::{AWGParams, Device, Protocol, Server},
    vault_file::VaultFile,
};
use cidr::parsers::parse_cidr_full;
use cidr::Ipv4Cidr;
use clap::Parser;
use inquire::Confirm;
use inquire::CustomType;
use inquire::{
    validator::Validation, CustomUserError, Password, PasswordDisplayMode, Select, Text,
};
use regex::Regex;
use secrecy::SecretString;

use colored::Colorize;

#[cfg(unix)]
use expanduser::expanduser;

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

    if vault.devices().is_empty() {
        println!("🤷 No devices in the vault");
    } else {
        for (id, device) in vault.devices() {
            println!("\n--- {}", device.name);
            println!("    ID: {}", id);
            println!("    User: {}", device.user);
            println!("    Public Key: {}", device.public_key_b64());
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

    let device = Device::new(name, user)?;

    println!("Saving...");
    ctx.vault.transact(|v| v.add_device(device))
}

fn do_remove_device(ctx: &mut Context) -> Result<()> {
    let vault = ctx.vault.vault();

    let choice = match Select::new(
        "Which device do you want to remove?",
        vault.make_device_choice_vec(),
    )
    .prompt_skippable()?
    {
        Some(n) => n,
        None => return Ok(()),
    };

    let confirm = Confirm::new("Are you sure you want to do remove this device? <y/n>")
        .with_help_message("Device private key will be permanently wiped")
        .prompt()?;

    if !confirm {
        return Ok(());
    }

    println!("Saving...");
    ctx.vault.transact(|v| v.remove_device(&choice.id))
}

fn do_generate_device_config(ctx: &mut Context) -> Result<()> {
    let vault = ctx.vault.vault();

    let device_entry =
        match Select::new("Select device:", vault.make_device_choice_vec()).prompt_skippable()? {
            Some(n) => n,
            None => return Ok(()),
        };

    let server_entry =
        match Select::new("Select server:", vault.make_server_choice_vec()).prompt_skippable()? {
            Some(n) => n,
            None => return Ok(()),
        };

    ctx.vault.transact(|v| {
        println!(
            "{}",
            v.generate_device_config(&device_entry.id, &server_entry.id)?
        );
        Ok(())
    })
}

fn do_view_servers(ctx: &Context) -> Result<()> {
    let vault = ctx.vault.vault();

    if vault.servers().is_empty() {
        println!("🤷 No servers in the vault");
    } else {
        for (_, server) in vault.servers() {
            println!("\n--- {}", server.name);
            println!("    ID: {}", server.id());
            println!("    Endpoint: {}", server.endpoint);
            println!("    Public Key: {}", server.public_key_b64());
            println!("    Client Network: {}", server.client_net());
            println!("    Addresses Used: {}", server.client_net_used());
            println!("    Addresses Available: {}", server.client_net_available());
        }
    }

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

    let client_net = CustomType::<Ipv4Cidr>::new("Enter CLIENT NETWORK:")
        .with_help_message("Use IPv4 CIDR format. Server itself will always use the first address")
        .with_parser(
            &|i| match parse_cidr_full(i, FromStr::from_str, FromStr::from_str) {
                Ok(val) => Ok(val),
                Err(_) => Err(()),
            },
        )
        .with_validator(|net: &Ipv4Cidr| {
            if net.is_host_address() {
                Ok(Validation::Invalid(
                    "It mush be a network, not a single host".into(),
                ))
            } else if net.network_length() > 26 {
                Ok(Validation::Invalid(
                    format!(
                        "At most /26 network is allowed, yours is /{}",
                        net.network_length()
                    )
                    .into(),
                ))
            } else {
                Ok(Validation::Valid)
            }
        })
        .with_placeholder("10.0.0.0/16")
        .prompt()?;

    let protocols = vec!["WireGuard", "AmneziaWG"];
    let protocol = match Select::new("Choose SERVER PROTOCOL:", protocols).prompt_skippable()? {
        Some(p) => match p {
            "WireGuard" => Protocol::WireGuard,
            "AmneziaWG" => Protocol::AmneziaWG(AWGParams::generate()),
            _ => return Ok(()),
        },
        None => return Ok(()),
    };

    let server = Server::new(name, endpoint, protocol, client_net);

    println!("Saving...");
    ctx.vault.transact(|v| v.add_server(server))
}

fn do_remove_server(ctx: &mut Context) -> Result<()> {
    let vault = ctx.vault.vault();

    let choice = match Select::new(
        "Which device do you want to remove?",
        vault.make_server_choice_vec(),
    )
    .prompt_skippable()?
    {
        Some(n) => n,
        None => return Ok(()),
    };

    let confirm = Confirm::new("Are you sure you want to do remove this server? <y/n>")
        .with_help_message("Server private key will be permanently wiped")
        .prompt()?;

    if !confirm {
        return Ok(());
    }

    println!("Saving...");
    ctx.vault.transact(|v| v.remove_server(&choice.id))
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

fn do_json_dump(ctx: &Context) -> Result<()> {
    let confirm = Confirm::new("Are you sure you want to do a JSON dump? <y/n>")
        .with_help_message("JSON dumps are NOT encrypted and store secrets in plaintext!")
        .prompt()?;

    if !confirm {
        return Ok(());
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open("awgdump.json")?;
    serde_json::to_writer_pretty(file, ctx.vault.vault())?;
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
        "[DEBUG] JSON dump",
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
            "Remove server" => do_remove_server(ctx),
            "Change password" => do_change_password(ctx),
            "Exit" => Err(anyhow!("Exit!")),
            "[DEBUG] Force save" => ctx.vault.save(),
            "[DEBUG] JSON dump" => do_json_dump(ctx),
            _ => Ok(()),
        },
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn process_path(s: &String) -> Result<PathBuf> {
    match expanduser(&s) {
        Ok(v) => Ok(v),
        Err(e) => Err(anyhow!("Failed to expand user: {}", e)),
    }
}

#[cfg(not(unix))]
fn process_path(s: &String) -> Result<PathBuf> {
    Ok(s.clone().into())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let vault_path = process_path(&args.vault_path)?;

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
                println!(
                    "Incorrect password or corruption! Details: {}",
                    result.err().unwrap()
                );
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
