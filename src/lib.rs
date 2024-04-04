#[macro_use]
extern crate bitflags;

use colored::Colorize;
use gadget::Gadget;
use std::fs;
use std::io::Write as _;
use std::sync::Arc;

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

pub fn collect_all_gadgets(sess: Session) -> GenericResult<Vec<Gadget>> {
    let info = &sess.info;
    let start_timestamp = std::time::Instant::now();
    let sections = info.format.sections();

    let use_color = sess.use_color;
    let unique_only = sess.unique_only;
    let chosen_output_format = sess.output.clone();
    let entrypoint_address = info.format.entry_point();
    let is_64b = info.is_64b();

    info!(
        "Looking for gadgets in {} executable section(s) (with {} threads)...'",
        sections.len(),
        sess.nb_thread,
    );

    //
    // use an arc for the session to share between threads
    //
    let arc = Arc::new(sess);
    match session::find_gadgets(arc.clone()) {
        Ok(_) => {
            debug!("Done collecting gadgets");
        }
        Err(e) => {
            error!("An error occured while collecting gadgets: {:?}", e);
            return Err(e);
        }
    }

    let mut gadgets = arc.gadgets.lock().unwrap();

    //
    // if unique, filter out doublons
    //
    let total_gadgets_found: usize = gadgets.len();
    if unique_only {
        debug!(
            "Filtering {} gadgets for deplicates ...",
            total_gadgets_found
        );
        gadgets.sort_by_key(|a| a.text(false));
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
    match chosen_output_format {
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
            dbg!(
                "Dumping {} gadgets to '{}'...",
                gadgets.len(),
                filename.to_str().unwrap()
            );

            if use_color {
                warn!("Disabling colors when writing to file");
            }

            let mut file = fs::File::create(&filename)?;
            for gadget in &*gadgets {
                let addr = entrypoint_address + gadget.address;
                file.write_all((format!("{:#x} | {}\n", addr, gadget.text(false))).as_bytes())?;
            }

            info!(
                "Written {} gadgets to '{}'",
                gadgets.len(),
                filename.to_str().unwrap()
            );
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

    Ok(gadgets.clone())
}

#[cfg(test)]
mod tests {
    use crate::{collect_all_gadgets, gadget::Gadget, session::RopGadgetOutput, Session};
    use std::path::PathBuf;

    fn run_basic_test(sz: &str, arch: &str, fmt: &str) -> Vec<Gadget> {
        let input_fname = PathBuf::from(format!("tests/bin/{}-{}.{}", sz, arch, fmt));
        let s = Session::new(input_fname).output(RopGadgetOutput::None);
        match collect_all_gadgets(s) {
            Ok(gadgets) => gadgets,
            Err(e) => panic!("{:?}", e),
        }
    }

    mod pe {
        use super::super::*;
        const FMT: &str = "pe";

        #[test]
        fn x86() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "x86", FMT);
                assert!(res.len() > 0);
            }
        }

        #[test]
        fn x64() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "x64", FMT);
                assert!(res.len() > 0);
            }
        }

        // #[test]
        // fn arm32() {
        //     for sz in ["small", "big"] {
        //         let res = tests::run_basic_test(sz, "arm32", FMT);
        //         assert!(res.len() > 0);
        //     }
        // }
        #[test]
        fn arm64() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "arm64", FMT);
                assert!(res.len() > 0);
            }
        }
    }

    mod elf {
        use super::super::*;
        const FMT: &str = "elf";

        #[test]
        fn x86() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "x86", FMT);
                assert!(res.len() > 0);
            }
        }

        #[test]
        fn x64() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "x64", FMT);
                assert!(res.len() > 0);
            }
        }

        // #[test]
        // fn arm32() {
        //     for sz in ["big", "small"] {
        //         let res = tests::run_basic_test(sz, "arm32", FMT);
        //         assert!(res.len() > 0);
        //     }
        // }
        #[test]
        fn arm64() {
            for sz in ["small", "big"] {
                let res = tests::run_basic_test(sz, "arm64", FMT);
                assert!(res.len() > 0);
            }
        }
    }

    mod macho {
        use super::super::*;
        const FMT: &str = "macho";

        #[test]
        fn x86() {
            for sz in vec!["small"] {
                let res = tests::run_basic_test(sz, "x86", FMT);
                assert!(res.len() > 0);
            }
        }

        #[test]
        fn x64() {
            for sz in vec!["small"] {
                let res = tests::run_basic_test(sz, "x64", FMT);
                assert!(res.len() > 0);
            }
        }
    }
}
