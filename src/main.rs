#[macro_use]
extern crate bitflags;

use std::fs;
use std::io::prelude::*;

use clap::{App, Arg};
use colored::*;
use log::{info, warn, error, trace};

mod common;
mod error;
mod gadget;
mod format;
mod section;
mod session;
mod cpu;
mod engine;

use common::GenericResult;
use session::Session;



fn main () -> GenericResult<()>
{
    let app = App::new("rp-rs")
        .version("0.1")
        .author("hugsy")
        .about("Another (bad) ROP gadget finder")

        .arg(
            Arg::new("file")
                .value_name("FILE")
                .about("The input file to check")
                .required(true)
        )

        .arg(
            Arg::with_name("thread_num")
                .short('t')
                .long("nb-threads")
                .about("The number of threads for processing the binary")
                .takes_value(true)
                .default_value("2")
        )

        .arg(
            Arg::with_name("output_file")
                .short('o')
                .long("output-file")
                .about("Write all gadgets into file")
                .takes_value(true)
        )

        .arg(
            Arg::with_name("unique")
                .short('u')
                .long("unique")
                .about("Show unique gadget only")
                .takes_value(false)
        )

        .arg(
            Arg::with_name("arch")
                .long("architecture")
                .about("Target architecture")
                .takes_value(true)
        )

        .arg(
            Arg::with_name("os")
                .long("os")
                .about("Target OS")
                .takes_value(true)
        )

        .arg(
            Arg::with_name("image_base")
                .long("imagebase")
                .about("Use VALUE as image base")
                .takes_value(true)
        )

        .arg(
            Arg::with_name("no_color")
                .long("no-color")
                .about("Don't colorize the output (only applies for stdout)")
                .takes_value(false)
        )

        .arg(
            Arg::with_name("verbosity")
                .short('v')
                .about("Increase verbosity (repeatable from 1 to 4)")
                .multiple(true)
                .takes_value(false)
        )

        .arg(
            Arg::with_name("max_gadget_length")
                .short('l')
                .long("max-gadget-len")
                .about("Maximum size of a gadget")
                .takes_value(true)
                .default_value("16")
        );

    let mut sess = Session::new(app).unwrap();
    trace!("{:?}", sess);

    if sess.is_valid_session()
    {
        info!("Creating new {}", sess);

        if let Some (sections) = &sess.sections
        {
            //
            // the real meat of the tool
            //
            info!("Looking for gadgets in {} sections (with {} threads)...'", sections.len(), sess.nb_thread);
            if !sess.find_gadgets()
            {
                error!("An error occured in `find_gadgets'");
                return Ok(());
            }


            let gadgets = &mut sess.gadgets;

            //
            // sort by address
            //
            gadgets.sort_by(|a,b | a.address.cmp(&b.address));


            //
            // if unique, filter out doublons
            //
            if sess.unique_only
            {
                info!("Filtering out deplicate gadgets...");
                gadgets.dedup_by(|a, b| a.text.eq_ignore_ascii_case(&b.text));
            }



            if let Some(filename) = sess.output_file
            {
                info!("Dumping {} gadgets to '{}'...", gadgets.len(), filename);
                let mut file = fs::File::create(filename)?;
                for g in gadgets
                {
                    let txt = g.text.as_str();
                    let addr = sess.info.entry_point_address + g.address;
                    file.write((format!("{:#x} | {}\n", addr, txt)).as_bytes())?;
                }
            }
            else
            {
                info!("Dumping {} gadgets to stdout...", gadgets.len());

                for g in gadgets
                {
                    let addr = match sess.info.is_64b()
                    {
                        true  => { format!("0x{:016x}", g.address) }
                        _ => { format!("0x{:08x}", g.address) }
                    };

                    //debug!("{} | {} | {:?}", addr, g.text, g.raw);

                    if sess.use_color
                    {
                        println!("{} | {}", addr.red(), g.text);
                    }
                    else
                    {
                        println!("{} | {}", addr, g.text);
                    }
                }
            }
            info!("Done!");
        }
    }
    else
    {
        warn!("Failed to build the session, check your parameters...");
    }

    sess.end_timestamp = std::time::Instant::now();

    if log::log_enabled!( log::Level::Info )
    {
        //let execution_time = sess.start_timestamp.elapsed().as_secs_f64();
        //info!("Execution time => {:?}", execution_time);
        info!("Execution: {} gadgets found in {:?}", sess.gadgets.len(), sess.end_timestamp - sess.start_timestamp);
    }

    Ok(())
}
