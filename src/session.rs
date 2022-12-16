use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use clap::{ArgAction, Parser, ValueEnum};
use colored::*;
use goblin::Object;
use log::{debug, error, info, warn, Level, LevelFilter, Metadata, Record};

use crate::common::GenericResult;
use crate::cpu;
use crate::engine::{DisassemblyEngine, DisassemblyEngineType};
use crate::format;
use crate::format::{elf, mach, pe, Format};
use crate::gadget::{
    find_gadgets_from_position, get_all_valid_positions_and_length, Gadget, InstructionGroup,
};
use crate::section::Section;

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
    Fast,
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
    pub format: Option<Format>,
    pub cpu: Option<Box<dyn cpu::Cpu>>,
    pub entry_point_address: u64,
}

impl std::fmt::Display for ExecutableDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cpu = match &self.cpu {
            Some(x) => x.cpu_type().to_string(),
            None => "Unknown".to_string(),
        };

        let format = match &self.format {
            Some(x) => {
                format!("{}", x)
            }
            None => "Unknown".to_string(),
        };

        write!(
            f,
            "Info({}, {}, Entry=0x{:x})",
            cpu, format, self.entry_point_address
        )
    }
}

impl ExecutableDetail {
    pub fn is_64b(&self) -> bool {
        if let Some(cpu) = &self.cpu {
            return cpu.ptrsize() == 8;
        }
        false
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
    pub sections: Option<Vec<Section>>,
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
    pub fn new() -> Option<Self> {
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

        let cpu: Option<Box<dyn cpu::Cpu>> = match args.architecture {
            Some(x) => match x {
                cpu::CpuType::X86 => Some(Box::new(cpu::x86::X86 {})),
                cpu::CpuType::X64 => Some(Box::new(cpu::x64::X64 {})),
                cpu::CpuType::ARM64 => Some(Box::new(cpu::arm::ARM64 {})),
                cpu::CpuType::ARM => Some(Box::new(cpu::arm::ARM {})),
            },
            None => None,
        };

        Some(Session {
            filepath: args.filepath,
            nb_thread: args.thread_num.into(),
            output_file: args.output_file,
            unique_only: args.unique_only,
            use_color: !args.no_color,
            max_gadget_length: args.max_insn_per_gadget.into(),
            gadget_type: args.rop_type,
            profile_type: args.profile_type,
            verbosity: verbosity,
            info: ExecutableDetail {
                format: args.format,
                entry_point_address: args.image_base.into(),
                cpu: cpu,
            },
            sections: None,
            gadgets: Mutex::new(Vec::new()),
            engine_type: DisassemblyEngineType::Capstone,
        })
    }

    ///
    /// Parse the given binary file
    ///
    fn collect_executable_section(&mut self) -> bool {
        if !self.filepath.as_path().exists() {
            return false;
        }

        let buffer = match fs::read(self.filepath.as_path()) {
            Ok(buf) => buf,
            Err(_) => panic!("failed to read {}", self.filepath.to_str().unwrap()),
        };

        let sections = match Object::parse(&buffer).unwrap() {
            Object::PE(pe) => Some(pe::prepare_pe_file(self, &pe).unwrap()),

            Object::Elf(elf) => Some(elf::prepare_elf_file(self, &elf).unwrap()),

            Object::Mach(mach) => Some(mach::prepare_mach_file(self, &mach).unwrap()),

            Object::Archive(_) => {
                error!("Unsupported type");
                None
            }

            Object::Unknown(magic) => {
                //TODO:
                //Some(mach::prepare_raw_file(self).unwrap())
                error!("unknown magic {}", magic);
                None
            }
        };

        match sections {
            Some(_) => {
                self.sections = sections;
                true
            }
            None => false,
        }
    }

    ///
    /// Parse the given binary file
    ///
    fn parse_binary_file(&mut self) -> bool {
        let filename = self.filepath.to_str().unwrap();

        info!("Checking file '{}'...", filename.green().bold());

        debug!(
            "Collecting executable sections from file '{}'...",
            filename.green().bold()
        );
        if !self.collect_executable_section() {
            return false;
        }

        //
        // todo: collect more info
        //

        true
    }

    ///
    /// Checks if the session is valid
    ///
    pub fn is_valid_session(&mut self) -> bool {
        info!("Checking session paramters...");

        self.parse_binary_file() && !self.sections.is_none()
    }
}

//
// find all the gadgets in the different sections in parallel
// returns true if no error occured
//
pub fn find_gadgets(session: Arc<Session>) -> bool {
    if session.sections.is_none() {
        return false;
    }

    let mut total_gadgets: usize = 0;
    let number_of_sections = session.sections.as_deref().unwrap().len();
    let nb_thread = session.nb_thread;

    //
    // multithread parsing of the sections (1 thread/section)
    //
    let mut i: usize = 0;

    while i < number_of_sections {
        let mut threads: Vec<std::thread::JoinHandle<Vec<Gadget>>> = Vec::new();

        for n in 0..nb_thread {
            debug!("spawning thread 'thread-{}'...", n);
            let c = session.clone();
            let thread = thread::spawn(move || thread_worker(c, i));
            threads.push(thread);
            i += 1;
        }

        for t in threads {
            debug!("joining {:?}...", t.thread().id());
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
        let cpu = match &self.info.cpu {
            Some(x) => x.cpu_type().to_string(),
            None => "Unknown".to_string(),
        };

        f.debug_struct("Session")
            .field("path", &self.filepath)
            .field("format", &Some(self.info.format.as_ref()))
            .field("cpu", &Some(cpu))
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
    if session.info.cpu.is_none() {
        panic!();
    }

    let cpu = session.info.cpu.as_ref().unwrap();
    let engine = DisassemblyEngine::new(&session.engine_type, cpu);
    debug!(
        "[{:?}] Initialized engine {} for {:?}",
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

    if let Some(sections) = &session.sections {
        if let Some(section) = sections.get(index) {
            debug!(
                "[Thread-{:?}] Processing section '{}'",
                thread::current().id(),
                section.name
            );

            let cpu = &session.info.cpu.as_ref().unwrap();

            for (pos, len) in get_all_valid_positions_and_length(&session, cpu, section)? {
                debug!(
                    "[Thread-{:?}] Processing {} (start_address={:x}, size={:x}) slice[..{:x}+{:x}] ",
                    thread::current().id(),
                    section.name, section.start_address, section.size, pos, len
                );

                let res = find_gadgets_from_position(engine, section, pos, len, cpu);

                if res.is_ok() {
                    let mut g = res?;
                    debug!("new {:?}", g);
                    gadgets.append(&mut g);
                }
            }

            debug!(
                "[Thread-{:?}] finished processing section '{}'",
                thread::current().id(),
                section.name
            );
        } else {
            warn!(
                "[Thread-{:?}] No section at index {}, ending...",
                thread::current().id(),
                index,
            );
        }
    } else {
        panic!(
            "[Thread-{:?}] process_section({:?}, {}) failed critically, aborting...",
            thread::current().id(),
            session,
            index
        );
    }

    Ok(gadgets)
}
