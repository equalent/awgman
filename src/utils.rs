use std::{fmt::Display, io::Write};

use crate::vault::PSK;
use anyhow::Result;
use crossterm::event::Event;
use nid::Nanoid;

pub struct NanoidEntry {
    pub id: Nanoid,
    pub display: String
}

impl Display for NanoidEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

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
