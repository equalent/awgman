use std::io::Write;

use crate::vault::PSK;
use anyhow::Result;
use crossterm::event::Event;

pub fn gen_psk() -> Result<PSK> {
    let mut psk = [0u8; 32];
    getrandom::fill(&mut psk)?;
    Ok(psk)
}

pub fn pause() {
    let mut stdout = std::io::stdout();

    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    loop {
        match crossterm::event::read() {
            Ok(e) => match e {
                Event::Key(_) => {
                    return;
                }
                _ => {}
            },
            Err(_) => {
                return;
            }
        }
    }
}
