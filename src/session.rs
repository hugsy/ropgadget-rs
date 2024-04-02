use std::borrow::Borrow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use clap::ValueEnum;
use colored::*;
use log::{debug, info, warn, Level, LevelFilter, Metadata, Record};

use crate::common::GenericResult;
use crate::cpu;
use crate::engine::{DisassemblyEngine, DisassemblyEngineType};
use crate::format::{self, guess_file_format};
use crate::gadget::{
    find_gadgets_from_position, get_all_valid_positions_and_length, Gadget, InstructionGroup,
};

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
pub enum RopProfileStrategy {
    #[default]
    /// Strategy Fast
    Fast,
    /// Strategy Complete
    Complete,
}

impl std::fmt::Display for RopProfileStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

pub struct ExecutableDetails {
    pub filepath: PathBuf,
    pub format: Box<dyn format::ExecutableFileFormat>,
    pub cpu: Box<dyn cpu::Cpu>,
}

impl std::fmt::Debug for ExecutableDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableDetails")
            .field("filepath", &self.filepath)
            .field("format", &self.format.format().to_string())
            .field("cpu", &self.cpu.cpu_type().to_string())
            .finish()
    }
}

impl std::fmt::Display for ExecutableDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Info({}, {}, Entry=0x{:x})",
            self.cpu.cpu_type(),
            self.format.format(),
            self.format.entry_point()
        )
    }
}

impl Default for ExecutableDetails {
    fn default() -> Self {
        ExecutableDetails {
            filepath: PathBuf::new(),
            cpu: Box::new(cpu::x86::X86 {}),
            format: Box::new(format::pe::Pe::default()),
        }
    }
}

impl ExecutableDetails {
    pub fn new(filepath: PathBuf) -> Self {
        let fpath = filepath.clone();
        let format = guess_file_format(&fpath).unwrap();

        let cpu: Box<dyn cpu::Cpu> = match format.cpu_type() {
            cpu::CpuType::X86 => Box::new(cpu::x86::X86 {}),
            cpu::CpuType::X64 => Box::new(cpu::x86::X64 {}),
            cpu::CpuType::ARM64 => Box::new(cpu::arm::Arm64 {}),
            cpu::CpuType::ARM => Box::new(cpu::arm::Arm {}),
            _ => panic!("CPU type is invalid"),
        };
        // let cpu = Box::new( Cpu::from(format.cpu_type()) );

        ExecutableDetails {
            filepath: fpath,
            cpu,
            format,
        }
    }

    pub fn is_64b(&self) -> bool {
        self.cpu.ptrsize() == 8
    }
}

#[derive(Debug, Clone, Default)]
pub enum RopGadgetOutput {
    #[default]
    None,
    Console,
    File(PathBuf),
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

#[derive(Debug)]
pub struct Session {
    //
    // session required information
    //
    pub info: ExecutableDetails,
    pub nb_thread: u8,
    pub verbosity: LevelFilter,
    pub output: RopGadgetOutput,

    //
    // misc details about the executable file (filled by )
    //

    // pub file_format: format::FileFormat,

    //
    // the info need to build, store and show the ropgadgets
    //
    pub engine_type: DisassemblyEngineType,
    pub max_gadget_length: usize,
    pub gadgets: Mutex<Vec<Gadget>>,
    pub unique_only: bool,
    pub use_color: bool,
    pub gadget_types: Vec<InstructionGroup>,
    pub profile_type: RopProfileStrategy,
}

impl Session {
    pub fn new(filepath: PathBuf) -> Self {
        Session {
            info: ExecutableDetails::new(filepath),
            ..Default::default()
        }
    }

    pub fn nb_thread(self, nb_thread: u8) -> Self {
        Self { nb_thread, ..self }
    }

    pub fn output(self, new_output: RopGadgetOutput) -> Self {
        Self {
            output: new_output,
            ..self
        }
    }

    pub fn unique_only(self, unique_only: bool) -> Self {
        Self {
            unique_only,
            ..self
        }
    }

    pub fn use_color(self, use_color: bool) -> Self {
        Self { use_color, ..self }
    }

    pub fn verbosity(self, verbosity: LevelFilter) -> Self {
        Self { verbosity, ..self }
    }

    pub fn filepath(&self) -> &PathBuf {
        &self.info.filepath
    }
}

impl Default for Session {
    fn default() -> Self {
        Session {
            verbosity: LevelFilter::Off,
            nb_thread: 4,
            output: RopGadgetOutput::None,
            unique_only: true,
            use_color: true,
            max_gadget_length: 6,
            gadget_types: vec![InstructionGroup::Ret],
            profile_type: RopProfileStrategy::Fast,
            gadgets: Mutex::new(Vec::new()),
            engine_type: DisassemblyEngineType::Capstone,
            info: ExecutableDetails::default(),
        }
    }
}

// impl std::fmt::Debug for Session {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Session")
//             .field("path", &self.filepath())
//             .field("format", &self.info.format.format().to_string())
//             .field("cpu", &self.info.cpu.cpu_type().to_string())
//             .finish()
//     }
// }

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gadget_types: Vec<String> = self.gadget_types.iter().map(|x| x.to_string()).collect();
        write!(
            f,
            "Session(File='{}', {}, Profile={}, GadgetTypes=[{}])",
            self.filepath().to_str().unwrap(),
            self.info,
            self.profile_type,
            gadget_types.join(", "),
        )
    }
}

///
/// This function manages the thread pool to look for gadget
///
pub fn find_gadgets(session: Arc<Session>) -> GenericResult<()> {
    let info = &session.info;
    let number_of_sections = info.format.sections().len();
    let nb_thread = session.nb_thread as usize;

    debug!("Using {nb_thread} threads over {number_of_sections} section(s) of executable code...");

    //
    // Multithread parsing of each section
    //
    for section_idx in 0..number_of_sections {
        if info.format.sections().get(section_idx).is_none() {
            continue;
        }

        let section = info.format.sections().get(section_idx).unwrap();
        let chunk_size = section.data.len() / nb_thread;

        //
        // Fill the thread pool
        //
        let mut threads: Vec<std::thread::JoinHandle<Vec<Gadget>>> = Vec::new();
        let mut pos = 0;
        let mut thread_pool_size = 0;
        let mut force_flush = false;

        loop {
            //
            // Empty the thread pool if necessary
            //
            if thread_pool_size == nb_thread || force_flush {
                for curthread in threads {
                    debug!("Joining {:?}...", curthread.thread().id());
                    let gadgets = curthread.join().unwrap();
                    {
                        let mut data = session.gadgets.lock().unwrap();
                        data.extend(gadgets);
                    }
                }

                threads = Vec::new();
                thread_pool_size = 0;

                if force_flush {
                    break;
                }
            }

            //
            // Is there still some data to parse?
            //
            if pos >= section.data.len() {
                force_flush = true;
                continue;
            }

            //
            // If so, spawn more workers
            //
            let rc_session = Arc::clone(&session);
            let thread = thread::spawn(move || thread_worker(rc_session, section_idx, pos));
            debug!(
                "Spawning {:?} (pos={} section_index={})...",
                thread.thread().id(),
                pos,
                section_idx
            );
            threads.push(thread);
            thread_pool_size += 1;
            pos += chunk_size;
        }
    }

    info!(
        "Total gadgets found => {}",
        session.gadgets.lock().unwrap().len()
    );
    Ok(())
}

///
/// Worker routine to search for gadgets
///
fn thread_worker(session: Arc<Session>, index: usize, cursor: usize) -> Vec<Gadget> {
    let cpu = session.info.cpu.as_ref();
    let engine = DisassemblyEngine::new(&session.engine_type, cpu);
    debug!(
        "{:?}: Initialized engine {} for {:?}",
        thread::current().id(),
        engine,
        cpu.cpu_type()
    );

    let mut gadgets: Vec<Gadget> = Vec::new();
    let sections = session.info.format.sections();
    if let Some(section) = sections.get(index) {
        let section_name = section
            .name
            .as_ref()
            .unwrap_or(String::from("N/A").borrow())
            .clone();

        debug!(
            "{:?}: Processing section '{}'",
            thread::current().id(),
            section_name
        );

        let cpu = &session.info.cpu;
        let disass = engine.disassembler.as_ref();

        for (pos, len) in
            get_all_valid_positions_and_length(&session, cpu, section, cursor).unwrap()
        {
            debug!(
                "{:?}: Processing Section {}[..{:x}+{:x}] (size={:x})",
                thread::current().id(),
                section_name,
                pos,
                len,
                section.size(),
            );

            let res = find_gadgets_from_position(session.clone(), disass, section, pos, len, cpu);
            if res.is_ok() {
                let mut gadget = res.unwrap();
                gadgets.append(&mut gadget);
            }
        }

        debug!(
            "{:?}: Finished processing section '{}'",
            thread::current().id(),
            section_name,
        );
    } else {
        warn!(
            "{:?}: No section at index {}, ending...",
            thread::current().id(),
            index,
        );
    }

    gadgets
}
