#[macro_use]
extern crate bitflags;

use clap::{App, Arg};
use colored::*;
use goblin::Object;
use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use log::{info, warn, error, debug, trace};


mod common;
mod error;
mod gadget;
mod format;
mod section;
mod session;
mod cpu;

use common::GenericResult;
use gadget::{get_all_return_positions, find_biggest_gadget_from_position, Gadget};
use format::{pe, elf, mach};
use session::Session;




fn process_section(section: &section::Section) -> GenericResult<Vec<Gadget>>
{
    let mut gadgets: Vec<Gadget> = Vec::new();

    for pos in get_all_return_positions(section)?
    {
        trace!("in {} return_insn at pos={:#x} (va={:#x})", section.name, pos, section.start_address+pos as u64);

        let res = find_biggest_gadget_from_position(section, pos);
        if res.is_err()
        {
            continue;
        }

        let gadget = res?;
        debug!("new {}", gadget);
        gadgets.push(gadget);
    }

    Ok(gadgets)
}


fn thread_worker(s: &section::Section) -> Vec<Gadget>
{
    let gadgets = process_section(s).unwrap();
    debug!("in {} - {} gadget(s) found", s.name.green().bold(), gadgets.len());
    gadgets
}


//
// returns true if no error occured
//
fn find_gadgets(session: &mut Session) -> bool
{
    let mut total_gadgets : usize = 0;

    if let Some(sections) = &session.sections
    {
        let nb_thread = session.nb_thread;

        //
        // multithread parsing of the sections
        //

        let mut i : usize = 0;

        while i < sections.len()
        {
            let mut threads : Vec<std::thread::JoinHandle<_>> = Vec::new();

            for n in 0..nb_thread
            {
                if let Some(section) = sections.get(i)
                {
                    let b= thread::Builder::new()
                        .name(std::fmt::format( std::format_args!("thread-{}", n)));
                    let s = section.clone(); // <-- HACK: this is ugly af and inefficient, learn to do better
                    let thread = b.spawn(move || thread_worker(&s));
                    debug!("spawning thread 'thread-{}'...", n);
                    threads.push(thread.unwrap());
                    i += 1;
                }
            }

            for t in threads
            {
                match t.thread().name()
                {
                    Some(x) => { debug!("joining {}", x); }
                    None => {}
                }

                let res = t.join();
                if res.is_ok()
                {
                    let gadgets = res.unwrap();
                    let cnt = gadgets.len();
                    session.gadgets.extend(gadgets);
                    total_gadgets += cnt;
                }
            }

        }

        debug!("total gadgets found => {}", total_gadgets);
    }

    true
}


///
/// parse the given binary file
///
fn collect_executable_section(session: &mut Session) -> bool
{
    let input = &session.filepath;
    let path = Path::new(input);
    let buffer = fs::read(path).unwrap();

    session.sections = match Object::parse(&buffer).unwrap()
    {
        Object::PE(pe) =>
        {
            Some( pe::prepare_pe_file(session, &pe).unwrap() )
        },

        Object::Elf(elf) =>
        {
            Some( elf::prepare_elf_file(session, &elf).unwrap())
        },

        Object::Mach(mach) =>
        {
            Some(mach::collect_executable_sections(&input, &mach).unwrap())
        }

        Object::Archive(_) =>
        {
            error!("Unsupported type");
            None
        },

        Object::Unknown(magic) =>
        {
            error!("unknown magic {}", magic);
            None
        },
    };

    match session.sections
    {
        Some(_) => {true}
        None => {false}
    }
}


fn parse_binary_file(session: &mut Session) -> bool
{
    if !collect_executable_section(session)
    {
        return false;
    }

    //
    // todo: collect more info
    //

    true
}


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
            Arg::with_name("verbosity")
                .short('v')
                .about("Increase verbosity (repeatable from 1 to 4)")
                .multiple(true)
                .takes_value(false)
        );

    let mut sess = Session::new(app).unwrap();

    trace!("{:?}", sess);

    info!("Checking file '{}'", sess.filepath.green().bold());

    if parse_binary_file(&mut sess)
    {
        info!("New {}", sess);

        if let Some (sections) = &sess.sections
        {
            info!("Looking for gadgets in {} sections (with {} threads)...'", sections.len(), sess.nb_thread);
            if !find_gadgets(&mut sess)
            {
                error!("An error occured in `find_gadgets'");
                return Ok(());
            }


            let gadgets = &sess.gadgets;

            if let Some(filename) = sess.output_file
            {
                info!("Dumping {} gadgets to '{}'...", gadgets.len(), filename);
                let mut file = fs::File::create(filename)?;
                for g in gadgets
                {
                    let txt = g.text.as_str();
                    let addr = sess.info.entry_point_address + g.addr;
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
                        true  => { format!("0x{:016x}", g.addr) }
                        _ => { format!("0x{:08x}", g.addr) }
                    };
                    println!("{} | {}", addr.red(), g.text);
                }
            }

            info!("Done!");
        }
    }
    else
    {
        warn!("Failed to parse the given file, check the command line arguments...");
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
