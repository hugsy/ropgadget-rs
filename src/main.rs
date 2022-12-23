#[macro_use]
extern crate bitflags;

use std::io::prelude::*;
use std::{fs, path::PathBuf};

use std::sync::Arc;

use colored::*;
use gadget::InstructionGroup;
use log::{debug, error, info, warn, LevelFilter};

mod common;
mod cpu;
mod engine;
mod error;
mod format;
mod gadget;
mod section;
mod session;

use common::GenericResult;
use session::{RopProfileStrategy, Session};

fn collect_all_gadgets(sess: Session) -> GenericResult<()> {
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
        "Looking for gadgets in {} executable section(s) (with {} threads)...'",
        sections.len(),
        sess.nb_thread,
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
        debug!(
            "Filtering {} gadgets for deplicates ...",
            total_gadgets_found
        );
        gadgets.dedup_by(|a, b| a.text(false).eq_ignore_ascii_case(&b.text(false)));
        info!(
            "{} duplicate gadgets removed",
            total_gadgets_found - gadgets.len()
        );
    }

    if let Some(filename) = outfile {
        info!(
            "Dumping {} gadgets to '{}'...",
            gadgets.len(),
            filename.to_str().unwrap()
        );
        if use_color {
            warn!("Disabling colors when writing to file");
        }

        let mut file = fs::File::create(filename)?;
        for g in &*gadgets {
            let txt = g.text(false);
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

fn main() -> GenericResult<()> {
    let sess = Session::new();
    info!("Created session: {}", sess);

    collect_all_gadgets(sess)
}

fn test_one(sz: &str, arch: &str, fmt: &str) -> bool {
    #![allow(dead_code)]
    let input_fname = PathBuf::from(format!("tests/bin/{}-{}.{}", sz, arch, fmt));
    let output_fname = PathBuf::from(format!("c:/temp/rop-{}-{}.{}", sz, arch, fmt));
    let s = Session {
        filepath: input_fname.clone(),
        nb_thread: 2,
        output_file: Some(output_fname),
        unique_only: true,
        use_color: false,
        max_gadget_length: 16,
        gadget_types: vec![InstructionGroup::Ret],
        profile_type: RopProfileStrategy::Fast,
        verbosity: LevelFilter::Debug,
        info: session::ExecutableDetail::new(&input_fname, None),
        gadgets: std::sync::Mutex::new(Vec::new()),
        engine_type: engine::DisassemblyEngineType::Capstone,
    };

    collect_all_gadgets(s).is_ok()
}

#[cfg(test)]
mod tests {

    mod pe {
        use super::super::*;
        const FMT: &str = "pe";

        #[test]
        fn x86() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "x86", FMT));
            }
        }

        #[test]
        fn x64() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "x64", FMT));
            }
        }

        #[test]
        fn arm32() {
            assert!(test_one("small", "arm32", FMT));
            assert!(test_one("big", "arm32", FMT));
        }

        #[test]
        fn arm64() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "arm64", FMT));
            }
        }
    }

    mod elf {
        use super::super::*;
        const FMT: &str = "elf";

        #[test]
        fn x86() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "x86", FMT));
            }
        }

        #[test]
        fn x64() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "x64", FMT));
            }
        }

        #[test]
        fn arm32() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "arm32", FMT));
            }
        }

        #[test]
        fn arm64() {
            for sz in vec!["small", "big"] {
                assert!(test_one(sz, "arm64", FMT));
            }
        }
    }

    mod macho {
        use super::super::*;
        const FMT: &str = "macho";

        #[test]
        fn x86() {
            for sz in vec!["small"] {
                assert!(test_one(sz, "x86", FMT));
            }
        }

        #[test]
        fn x64() {
            for sz in vec!["small"] {
                assert!(test_one(sz, "x64", FMT));
            }
        }
    }
}
