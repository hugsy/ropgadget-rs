#[macro_use]
extern crate bitflags;

use colored::Colorize;
use std::io::Write as _;
use std::sync::Arc;
use std::{fs, path::PathBuf};

use log::{debug, error, info, warn};

pub mod common;
pub mod cpu;
pub mod engine;
pub mod error;
pub mod format;
pub mod gadget;
pub mod section;
pub mod session;

use crate::common::GenericResult;
use crate::session::Session;

pub fn collect_all_gadgets(sess: Session) -> GenericResult<()> {
    let info = &sess.info;
    let start_timestamp = std::time::Instant::now();
    let sections = info.format.sections();
    let total_gadgets_found: usize;
    let use_color = sess.use_color.clone();
    let unique_only = sess.unique_only.clone();
    let _output = sess.output.clone();
    let entrypoint_address = info.format.entry_point().clone();
    let is_64b = info.is_64b();

    //
    // the real meat of the tool
    //
    info!(
        "Looking for gadgets in {} executable section(s) (with {} threads)...'",
        sections.len(),
        sess.nb_thread,
    );

    let arc = Arc::new(sess);
    let res = session::find_gadgets(arc.clone());
    if res.is_err() {
        error!("An error occured while collecting gadgets");
        return res;
    }

    let mut gadgets = arc.gadgets.lock().unwrap();

    //
    // if unique, filter out doublons
    //
    total_gadgets_found = gadgets.len();
    if unique_only {
        debug!(
            "Filtering {} gadgets for deplicates ...",
            total_gadgets_found
        );
        gadgets.sort_by(|a, b| a.text(false).cmp(&b.text(false)));
        gadgets.dedup_by(|a, b| a.text(false).eq_ignore_ascii_case(b.text(false).as_str()));
        info!(
            "{} duplicate gadgets removed",
            total_gadgets_found - gadgets.len()
        );
    }

    //
    // sort by address
    //
    gadgets.sort_by(|a, b| a.address.cmp(&b.address));

    //
    // Write to given output
    //
    match _output {
        session::RopGadgetOutput::None => {
            warn!("No output specified");
        }

        session::RopGadgetOutput::Console => {
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

        session::RopGadgetOutput::File(filename) => {
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

fn test_one(sz: &str, arch: &str, fmt: &str) -> bool {
    #![allow(dead_code)]
    let input_fname = PathBuf::from(format!("tests/bin/{}-{}.{}", sz, arch, fmt));
    // let mut output_fname = std::env::temp_dir();
    // output_fname.push(format!("rop-{}-{}.{}", sz, arch, fmt));
    // let s = Session {
    //     filepath: input_fname.clone(),
    //     nb_thread: 2,
    //     output: RopGadgetOutput::Console,
    //     unique_only: true,
    //     use_color: false,
    //     max_gadget_length: 16,
    //     gadget_types: vec![InstructionGroup::Ret],
    //     profile_type: RopProfileStrategy::Fast,
    //     verbosity: LevelFilter::Debug,
    //     gadgets: std::sync::Mutex::new(Vec::new()),
    //     engine_type: engine::DisassemblyEngineType::Capstone,
    //     ..Default::default()
    // };

    let s = Session::new(input_fname);

    collect_all_gadgets(s).is_ok()

    // fs::remove_file(output_fname.as_path()).unwrap();

    // res
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
            for sz in vec!["big"] {
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
