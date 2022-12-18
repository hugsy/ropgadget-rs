#[macro_use]
extern crate bitflags;

use std::fs;
use std::io::prelude::*;

use std::sync::Arc;

use colored::*;
use log::{error, info};

mod common;
mod cpu;
mod engine;
mod error;
mod format;
mod gadget;
mod section;
mod session;

use common::GenericResult;
use session::Session;

fn main() -> GenericResult<()> {
    let sess = Session::new();
    info!("Created session: {}", sess);

    let start_timestamp = std::time::Instant::now();

    let sections = sess.info.format.sections();
    let total_gadgets_found: usize;
    let use_color = sess.use_color.clone();
    let unique_only = sess.unique_only.clone();
    let outfile = sess.output_file.clone();
    let entrypoint_address = sess.info.format.entry_point().clone();
    let is_64b = sess.info.is_64b();

    //
    // the real meat of the tool
    //
    info!(
        "Looking for gadgets in {} executable sections (with {} threads)...'",
        sections.len(),
        sess.nb_thread
    );

    let arc = Arc::new(sess);
    {
        if !session::find_gadgets(arc.clone()) {
            error!("An error occured in `find_gadgets'");
            return Ok(());
        }
    }

    //
    // sort by address
    //
    let mut gadgets = arc.gadgets.lock().unwrap();
    gadgets.sort_by(|a, b| a.address.cmp(&b.address));

    total_gadgets_found = gadgets.len();

    //
    // if unique, filter out doublons
    //
    if unique_only {
        info!("Filtering out deplicate gadgets...");
        gadgets.dedup_by(|a, b| a.text(false).eq_ignore_ascii_case(&b.text(false)));
    }

    if let Some(filename) = outfile {
        info!(
            "Dumping {} gadgets to '{}'...",
            gadgets.len(),
            filename.to_str().unwrap()
        );
        let mut file = fs::File::create(filename)?;
        for g in &*gadgets {
            let txt = g.text(use_color);
            let addr = entrypoint_address + g.address;
            file.write((format!("{:#x} | {}\n", addr, txt)).as_bytes())?;
        }
    } else {
        info!("Dumping {} gadgets to stdout...", gadgets.len());

        for g in &*gadgets {
            let addr = match is_64b {
                true => {
                    format!("0x{:016x}", g.address)
                }
                _ => {
                    format!("0x{:08x}", g.address)
                }
            };

            if use_color {
                println!("{} | {}", addr.red(), g.text(use_color));
            } else {
                println!("{} | {}", addr, g.text(use_color));
            }
        }
    }

    info!("Done!");

    if log::log_enabled!(log::Level::Info) {
        let end_timestamp = std::time::Instant::now();
        let elapsed = end_timestamp - start_timestamp;
        let execution_time = start_timestamp.elapsed().as_secs_f64();
        info!("Execution time => {:?}", execution_time);
        info!(
            "Execution: {} gadgets found in {:?}",
            total_gadgets_found, elapsed
        );
    }

    Ok(())
}
