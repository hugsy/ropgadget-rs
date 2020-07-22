#[macro_use]
extern crate bitflags;

use std::fs;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::sync::Arc;

use clap::{App, Arg};
use colored::*;
use goblin::Object;
use log::{info, warn, error, debug, trace};

mod common;
mod error;
mod gadget;
mod format;
mod section;
mod session;
mod cpu;
mod engine;


use common::GenericResult;
use gadget::{get_all_return_positions, find_gadgets_from_position, Gadget};
use format::{pe, elf, mach};
use session::Session;
use engine::{DisassemblyEngine, DisassemblyEngineType};



fn process_section(engine: &DisassemblyEngine, section: &section::Section, cpu: Arc<dyn cpu::Cpu>, use_color: bool) -> GenericResult<Vec<Gadget>>
{
    let mut gadgets: Vec<Gadget> = Vec::new();

    for pos in get_all_return_positions(&cpu, section)?
    {
        trace!("[{}] {:x} data[..{:x}]", section.name, section.start_address, pos);

        let data = &section.data[(pos-10)..pos+1]; // todo: use session.max_gadget_length
        let res = find_gadgets_from_position(
            engine,
            data,
            section.start_address,
            pos,
            &cpu,
            use_color
        );

        if res.is_ok()
        {
            let mut g = res?;
            debug!("new {:?}", g);
            gadgets.append(&mut g);
        }

        //break;
    }

    Ok(gadgets)
}


fn thread_worker(section: &section::Section, cpu: Arc<dyn cpu::Cpu>, use_color: bool) -> Vec<Gadget>
{
    let engine = DisassemblyEngine::new(DisassemblyEngineType::Capstone, cpu.as_ref());
    debug!("using engine: {}", &engine);
    let gadgets = process_section(&engine, section, cpu, use_color).unwrap();
    debug!("in {} - {} gadget(s) found", section.name.green().bold(), gadgets.len());
    gadgets
}


//
// returns true if no error occured
//
fn find_gadgets(session: &mut Session) -> bool
{
    let mut total_gadgets : usize = 0;
    let use_color = session.use_color.clone();

    if let Some(sections) = &session.sections
    {
        let nb_thread = session.nb_thread;


        //
        // multithread parsing of the sections (1 thread/section)
        //

        let mut i : usize = 0;

        let cpu: Arc<dyn cpu::Cpu> = match session.info.cpu.as_ref().unwrap().cpu_type()
        {
            cpu::CpuType::X86 => {Arc::new(cpu::x86::X86{})}
            cpu::CpuType::X64 => {Arc::new(cpu::x64::X64{})}
        };

        while i < sections.len()
        {
            let mut threads : Vec<std::thread::JoinHandle<_>> = Vec::new();

            for n in 0..nb_thread
            {
                if let Some(section) = sections.get(i)
                {
                    let b= thread::Builder::new()
                        .name(std::fmt::format( std::format_args!("thread-{}", n)));
                    let c = cpu.clone();
                    let s = section.clone(); // <-- HACK: this is ugly af and inefficient, learn to do better
                    let thread = b.spawn(move || thread_worker(&s, c, use_color));
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
                .default_value("8")
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


            let gadgets = &mut sess.gadgets;

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
                gadgets.sort_by(|a,b | a.address.cmp(&b.address));
                for g in gadgets
                {
                    let addr = match sess.info.is_64b()
                    {
                        true  => { format!("0x{:016x}", g.address) }
                        _ => { format!("0x{:08x}", g.address) }
                    };

                    //println!("{} | {} | {:?}", addr, g.text, g.raw);

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
