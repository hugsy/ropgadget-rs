use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use clap::{ArgAction, Parser, ValueEnum};
use colored::*;
use log::{debug, info, warn, Level, LevelFilter, Metadata, Record};

use crate::common::GenericResult;
use crate::cpu;
use crate::engine::{DisassemblyEngine, DisassemblyEngineType};
use crate::format::{self, guess_file_format};
use crate::gadget::{
    find_gadgets_from_position, get_all_valid_positions_and_length, Gadget, InstructionGroup,
};

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RopGadgetType {
    /// Any
    Any,
    /// Returns only
    Returns,
    /// Calls only
    Calls,
    /// Jumps
    Jumps,
}

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RopProfileStrategy {
    /// Strategy Fast
    Fast,
    /// Strategy Complete
    Complete,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)] // Read from `Cargo.toml`
pub struct Args {
    /// The file to parse
    #[arg(value_name = "FILE")]
    filepath: PathBuf,

    /// The number of threads to use
    #[arg(short, long = "number-of-threads", default_value_t = 2)]
    thread_num: u8,

    /// Write gadget to file (optional)
    #[arg(short, long = "output-file", value_name = "OUTPUT")]
    output_file: Option<PathBuf>,

    /// The verbosity level
    #[arg(short, long = "verbose", action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Unique gadgets
    #[arg(short, long, action = ArgAction::SetTrue)]
    unique_only: bool,

    /// Force the architecture to given value
    #[arg(long, value_enum)]
    architecture: Option<cpu::CpuType>,

    /// Force the OS to given value
    #[arg(long, value_enum)]
    format: Option<format::Format>,

    /// Specify an image base
    #[arg(short, long, default_value_t = 0)]
    image_base: u32,

    /// Unique gadgets
    #[arg(long)]
    no_color: bool,

    /// The maximum number of instructions in a gadget
    #[arg(long, default_value_t = 6)]
    max_insn_per_gadget: u8,

    /// The type of gadgets to focus on (default - any)
    #[arg(long, value_enum, default_value_t = InstructionGroup::Undefined)]
    rop_type: InstructionGroup,

    /// The profile type (default - fast)
    #[arg(long, value_enum, default_value_t = RopProfileStrategy::Fast)]
    profile_type: RopProfileStrategy,
}

pub struct ExecutableDetail {
    pub format: Box<dyn format::ExecutableFormat>,
    pub cpu: Box<dyn cpu::Cpu>,
}

impl std::fmt::Display for ExecutableDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Info({}, {}, Entry=0x{:x})",
            self.cpu.cpu_type().to_string(),
            self.format.format().to_string(),
            self.format.entry_point()
        )
    }
}

impl ExecutableDetail {
    pub fn new(filepath: &PathBuf, binfmt: Option<format::Format>) -> Self {
        let format = guess_file_format(&filepath).unwrap();
        let cpu_type = format.cpu().cpu_type();
        let cpu: Box<dyn cpu::Cpu> = match cpu_type {
            cpu::CpuType::X86 => Box::new(cpu::x86::X86 {}),
            cpu::CpuType::X64 => Box::new(cpu::x86::X64 {}),
            cpu::CpuType::ARM64 => Box::new(cpu::arm::Arm64 {}),
            cpu::CpuType::ARM => Box::new(cpu::arm::Arm {}),
        };

        let check_format = match binfmt {
            Some(fmt) => fmt == format.format(),
            _ => true,
        };

        if !check_format {
            panic!("A binary format was specify, but doesn't match the given file...")
        }

        ExecutableDetail { cpu, format }
    }

    pub fn is_64b(&self) -> bool {
        self.cpu.ptrsize() == 8
    }
}

struct RpLogger;

impl log::Log for RpLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = match record.level().to_string().as_str() {
                "ERROR" => "ERROR".red(),
                "WARN" => "WARN".magenta(),
                "INFO" => "INFO".green(),
                "DEBUG" => "DEBUG".cyan(),
                _ => "TRACE".bold(),
            };

            println!("[{}] - {}", level, record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: RpLogger = RpLogger;

pub struct Session {
    //
    // session required information
    //
    pub filepath: PathBuf,
    pub nb_thread: u32,
    pub verbosity: LevelFilter,
    pub output_file: Option<PathBuf>,

    //
    // misc details about the executable file (filled by )
    //
    pub info: ExecutableDetail,

    //
    // the info need to build, store and show the ropgadgets
    //
    engine_type: DisassemblyEngineType,
    pub max_gadget_length: usize,
    pub gadgets: Mutex<Vec<Gadget>>,
    pub unique_only: bool,
    pub use_color: bool,
    pub gadget_type: InstructionGroup,
    pub profile_type: RopProfileStrategy,
}

impl Session {
    //
    // Build session parameters
    //
    pub fn new() -> Self {
        let args = Args::parse();

        let verbosity = match args.verbosity {
            4 => LevelFilter::Trace, // -vvvv
            3 => LevelFilter::Debug, // -vvv
            2 => LevelFilter::Info,  // -vv
            1 => LevelFilter::Warn,  // -v
            _ => LevelFilter::Error,
        };

        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(verbosity))
            .unwrap();

        let info = ExecutableDetail::new(&args.filepath, args.format);

        Session {
            filepath: args.filepath,
            nb_thread: args.thread_num.into(),
            output_file: args.output_file,
            unique_only: args.unique_only,
            use_color: !args.no_color,
            max_gadget_length: args.max_insn_per_gadget.into(),
            gadget_type: args.rop_type,
            profile_type: args.profile_type,
            verbosity: verbosity,
            info: info,
            gadgets: Mutex::new(Vec::new()),
            engine_type: DisassemblyEngineType::Capstone,
        }
    }
}

//
// find all the gadgets in the different sections in parallel
// returns true if no error occured
//
pub fn find_gadgets(session: Arc<Session>) -> bool {
    let mut total_gadgets: usize = 0;
    let number_of_sections = session.info.format.sections().len();
    let nb_thread = session.nb_thread;

    debug!(
        "Using {} threads over {} sections of executable code...",
        nb_thread, number_of_sections
    );

    //
    // multithread parsing of the sections (1 thread/section)
    //
    let mut i: usize = 0;

    while i < number_of_sections {
        let mut threads: Vec<std::thread::JoinHandle<Vec<Gadget>>> = Vec::new();

        for n in 0..nb_thread {
            debug!("Spawning thread 'thread-{}'...", n);
            let c = session.clone();
            let thread = thread::spawn(move || thread_worker(c, i));
            threads.push(thread);
            i += 1;
        }

        for t in threads {
            debug!("Joining {:?}...", t.thread().id());
            let gadgets = t.join().unwrap();
            let cnt = gadgets.len().clone();
            {
                let mut data = session.gadgets.lock().unwrap();
                data.extend(gadgets);
            }
            total_gadgets += cnt;
        }
    }

    info!("Total gadgets found => {}", total_gadgets);
    true
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.filepath)
            .field("format", &self.info.format.format().to_string())
            .field("cpu", &self.info.cpu.cpu_type().to_string())
            .finish()
    }
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session(file={}, {})",
            self.filepath.to_str().unwrap_or("<NoFile>"),
            self.info
        )
    }
}

fn thread_worker(session: Arc<Session>, index: usize) -> Vec<Gadget> {
    let cpu = session.info.cpu.as_ref();
    let engine = DisassemblyEngine::new(&session.engine_type, cpu);
    debug!(
        "{:?}: Initialized engine {} for {:?}",
        thread::current().id(),
        engine,
        cpu.cpu_type()
    );
    process_section(session, index, &engine).unwrap()
}

fn process_section(
    session: Arc<Session>,
    index: usize,
    engine: &DisassemblyEngine,
) -> GenericResult<Vec<Gadget>> {
    let mut gadgets: Vec<Gadget> = Vec::new();
    let sections = session.info.format.sections();
    if let Some(section) = sections.get(index) {
        debug!(
            "{:?}: Processing section '{}'",
            thread::current().id(),
            section.name
        );

        let cpu = &session.info.cpu;

        for (pos, len) in get_all_valid_positions_and_length(&session, cpu, section)? {
            debug!(
                "{:?}: Processing {} (start_address={:x}, size={:x}) slice[..{:x}+{:x}] ",
                thread::current().id(),
                section.name,
                section.start_address,
                section.size,
                pos,
                len
            );

            let res = find_gadgets_from_position(engine, section, pos, len, cpu);
            if res.is_ok() {
                let mut g = res?;
                debug!("new {:?}", g);
                gadgets.append(&mut g);
            }
        }

        debug!(
            "{:?}: Finished processing section '{}'",
            thread::current().id(),
            section.name
        );
    } else {
        warn!(
            "{:?}: No section at index {}, ending...",
            thread::current().id(),
            index,
        );
    }

    Ok(gadgets)
}
