use std::path::absolute;

use anyhow::{anyhow, Result};
use awgman::vault_file::VaultFile;
use clap::Parser;
use expanduser::expanduser;
use inquire::{validator::Validation, CustomUserError, Password, PasswordDisplayMode};
use regex::Regex;
use secrecy::SecretString;

use colored::Colorize;

#[derive(Parser, Debug)]
#[command(version)]
#[command(about = "WireGuard/AmneziaWG keychain and manager TUI")]
struct Args {
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(help = "Path to the vault file", default_value = "awgvault.db")]
    vault_path: String,
}

fn validate_password(password: &str) -> Result<Validation, CustomUserError> {
    if password.len() < 12 {
        return Ok(Validation::Invalid("Password must be at least 12 characters long.".into()));
    }
    if !Regex::new(r"[a-z]").unwrap().is_match(password) {
        return Ok(Validation::Invalid("Password must contain at least one lowercase letter.".into()));
    }
    if !Regex::new(r"[A-Z]").unwrap().is_match(password) {
        return Ok(Validation::Invalid("Password must contain at least one uppercase letter.".into()));
    }
    if !Regex::new(r"\d").unwrap().is_match(password) {
        return Ok(Validation::Invalid("Password must contain at least one number.".into()));
    }
    if !Regex::new(r"[^\w\s]").unwrap().is_match(password) {
        return Ok(Validation::Invalid("Password must contain at least one special character.".into()));
    }
    if Regex::new(r"\s").unwrap().is_match(password) {
        return Ok(Validation::Invalid("Password must not contain whitespace.".into()));
    }
    Ok(Validation::Valid)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let vault_path = expanduser(&args.vault_path)?;

    let mut vault: VaultFile;

    if vault_path.is_file() {
        println!("Opening existing vault...");

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
        println!("Vault will be created here: {}", absolute(&vault_path)?.display());
        println!("\n{}", "(tip: use Ctrl+R to reveal password)".dimmed().italic());
        println!("{}", "(tip: use ESC to cancel creation)".dimmed().italic());

        let password = SecretString::from(
            Password::new("Enter password:")
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_validator(validate_password)
                .prompt_skippable()?
                .ok_or_else(|| anyhow!("Vault creation cancelled"))?
            );
        vault = VaultFile::create(&vault_path, &password)?;
    }

    drop(vault);

    Ok(())
}
