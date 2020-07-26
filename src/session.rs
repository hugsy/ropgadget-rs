use std::fs;
use std::thread;

use std::sync::Arc;
use std::path::Path;

use clap::App;
use colored::*;
use log::{
    Record, Level, Metadata, LevelFilter,
    debug, info, error, trace
};
use goblin::Object;

use crate::common::GenericResult;
use crate::format::{Format, pe, elf, mach};
use crate::cpu;
use crate::section::Section;
use crate::gadget::{get_all_return_positions, find_gadgets_from_position, Gadget};
use crate::engine::{DisassemblyEngine, DisassemblyEngineType};



pub struct ExecutableDetail
{
    pub format: Option<Format>,
    pub cpu: Option<Box<dyn cpu::Cpu + Send + Sync>>,
    pub entry_point_address: u64,
}


impl std::fmt::Display for ExecutableDetail
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let cpu = match &self.cpu
        {
            Some(x) => { x.cpu_type().to_string() }
            None => { "Unknown".to_string() }
        };

        let format = match &self.format
        {
            Some(x) => { format!("{}", x) }
            None => { "Unknown".to_string() }
        };

        write!(f, "Info({}, {}, Entry=0x{:x})", cpu, format, self.entry_point_address)
    }
}

impl ExecutableDetail
{
    pub fn is_64b(&self) -> bool
    {
        match &self.cpu
        {
            Some(cpu) => { cpu.ptrsize() == 8 }
            None => { false }
        }
    }
}


struct RpLogger;

impl log::Log for RpLogger
{
    fn enabled(&self, metadata: &Metadata) -> bool
    {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record)
    {
        if self.enabled(record.metadata())
        {
            let level = match record.level().to_string().as_str()
            {
                "ERROR" => { "ERROR".red() },
                "WARN" => { "WARN".magenta() },
                "INFO" => { "INFO".green() },
                "DEBUG" => { "DEBUG".cyan() },
                _ => { "TRACE".bold() },
            };

            println!("[{}] - {}", level, record.args());
        }
    }

    fn flush(&self) {}
}


static LOGGER: RpLogger = RpLogger;


pub struct Session
{
    //
    // session required information
    //
    pub filepath: String,
    pub nb_thread: u32,
    pub verbosity: LevelFilter,
    pub output_file: Option<String>,
    pub start_timestamp: std::time::Instant,
    pub end_timestamp: std::time::Instant,

    //
    // misc details about the executable file (filled by )
    //
    pub info: ExecutableDetail,

    //
    // the info need to build, store and show the ropgadgets
    //
    pub sections: Option<Vec<Section>>,
    pub max_gadget_length: usize,
    pub gadgets: Vec<Gadget>,
    pub unique_only: bool,
    pub use_color: bool,
}



impl Session
{
    //
    // Build session parameters
    //
    pub fn new(args: App) -> Option<Self>
    {
        let matches = args.get_matches();

        let filepath = match matches.value_of("file")
        {
            Some(x) =>
            {
                let p = std::path::Path::new(x);
                if p.exists() && p.is_file()
                {
                    x.to_ascii_lowercase()
                }
                else
                {
                    println!("'{}' is invalid", x.bold().green());
                    return None;
                }
            },
            None =>
            {
                panic!("FILE argument is required")
            }
        };

        let nb_thread = match matches.value_of("thread_num")
        {
            Some(x) => { x.parse::<u32>().unwrap() }
            None => { 2 }
        };

        let verbosity = match matches.values_of("verbosity")
        {
            Some(_x) =>
            {
                let cnt = matches.occurrences_of("verbosity");
                match cnt
                {
                    4 => { LevelFilter::Trace } // -vvvv
                    3 => { LevelFilter::Debug } // -vvv
                    2 => { LevelFilter::Info } // -vv
                    1 => { LevelFilter::Warn } // -v
                    _ => { LevelFilter::Error }
                }
            },
            None => { LevelFilter::Error }
        };

        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(verbosity))
            .unwrap();


        let output_file = match matches.value_of("output_file")
        {
            Some(x) => { Some(x.to_string()) }
            None => { None }
        };

        //
        // if the --os option is given, the user tries to force the format
        //
        let format = match matches.value_of("os")
        {
            Some(x) =>
            {
                match x
                {
                    "win" => { Some(Format::Pe) }
                    "lin" => { Some(Format::Elf) }
                    "osx" => { todo!("soon") }
                    "raw" => { todo!("soon") }
                    _ => { unimplemented!("unknown {}", x) }
                }
            }
            None => { None }
        };

        //
        // if the --arch option is given, the user tries to force the format
        //
        let cpu: Option<Box<dyn cpu::Cpu + std::marker::Send + std::marker::Sync>> = match matches.value_of("arch")
        {
            Some(x) =>
            {
                match x
                {
                    "x86" => { Some(Box::new(cpu::x86::X86{})) }
                    "x64" => { Some(Box::new(cpu::x64::X64{})) }
                    "arm" => { todo!("soon") }
                    "arm64" => { todo!("soon") }
                    _ => { unimplemented!("unknown {}", x) }
                }
            }
            None => { None }
        };



        let entry_point_address : u64 = match matches.value_of("image_base")
        {
            Some(x) =>
            {
                //
                // if specified by flag --imagebase
                //
                x.parse::<u64>().unwrap_or(0)
            }
            None =>
            {
                //
                // default value
                //
                match &cpu
                {
                    Some(x) =>
                    {
                        match x.ptrsize()
                        {
                            4 => { 0x00000000 }
                            8 => { 0x0000000140000000 }
                            _ => { 0x00000000 }
                        }
                    }
                    None => { 0x00000000 }
                }
            }
        };


        let unique_only = matches.is_present("unique");

        let mut use_color = !matches.is_present("no_color");

        //
        // if the output is redirected to a file, disregard the colorize setting anyway
        //
        match output_file
        {
            Some(_) => { use_color = false; }
            _ => { }
        }

        let max_gadget_length = match matches.value_of("max_gadget_length")
        {
            Some(x) => { x.parse::<usize>().unwrap() }
            None => { 16 }
        };


        Some(
            Session
            {
                filepath,
                nb_thread,
                verbosity,
                output_file,
                start_timestamp: std::time::Instant::now(),
                end_timestamp: std::time::Instant::now(),
                info: ExecutableDetail
                {
                    format,
                    cpu,
                    entry_point_address: entry_point_address,
                },
                sections: None,
                gadgets: Vec::new(),
                unique_only,
                use_color,
                max_gadget_length,
            }
        )
    }


    ///
    /// Parse the given binary file
    ///
    fn collect_executable_section(&mut self) -> bool
    {
        let input = &self.filepath;
        let path = Path::new(input);
        let buffer = fs::read(path).unwrap();

        let sections = match Object::parse(&buffer).unwrap()
        {
            Object::PE(pe) =>
            {
                Some( pe::prepare_pe_file(self, &pe).unwrap() )
            },

            Object::Elf(elf) =>
            {
                Some( elf::prepare_elf_file( self, &elf).unwrap())
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

        match sections
        {
            Some(_) => {self.sections = sections; true}
            None => {false}
        }
    }


    ///
    /// Parse the given binary file
    ///
    fn parse_binary_file(&mut self) -> bool
    {
        debug!("Checking file '{}'", self.filepath.green().bold());

        if !self.collect_executable_section()
        {
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
    pub fn is_valid_session(&mut self) -> bool
    {
        info!("Checking session paramters...");

        self.parse_binary_file() && !self.sections.is_none()
    }



    //
    // find all the gadgets in the different sections in parallel
    // returns true if no error occured
    //
    pub fn find_gadgets(&mut self) -> bool
    {
        let mut total_gadgets : usize = 0;
        let use_color = self.use_color;

        if let Some(sections) = &self.sections
        {
            let nb_thread = self.nb_thread;


            //
            // multithread parsing of the sections (1 thread/section)
            //

            let mut i : usize = 0;

            let cpu: Arc<dyn cpu::Cpu> = match self.info.cpu.as_ref().unwrap().cpu_type()
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
                        let c = cpu.clone();
                        let s = section.clone(); // <-- HACK: this is ugly af and inefficient, learn to do better
                        let thread = thread::spawn(move || thread_worker(&s, c, use_color));
                        debug!("spawning thread 'thread-{}'...", n);
                        threads.push(thread);
                        i += 1;
                    }
                }

                for t in threads
                {
                    debug!("joining {:?}", t.thread().id());

                    let res = t.join();
                    if res.is_ok()
                    {
                        let gadgets = res.unwrap();
                        let cnt = gadgets.len();
                        &self.gadgets.extend(gadgets);
                        total_gadgets += cnt;
                    }
                }

            }

            debug!("total gadgets found => {}", total_gadgets);
        }

        true
    }


}


impl std::fmt::Debug for Session
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let cpu = match &self.info.cpu
        {
            Some(x) => { x.cpu_type().to_string() }
            None => { "Unknown".to_string() }
        };

        f.debug_struct("Session")
            .field("path", &self.filepath)
            .field("format", &Some(self.info.format.as_ref()))
            .field("cpu", &Some(cpu))
            .finish()
    }
}


impl std::fmt::Display for Session
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(
            f,
            "Session(file={}, {})",
            self.filepath,
            self.info
        )
    }
}




/*
fn thread_worker(section: &Section, cpu: Arc<dyn cpu::Cpu>, use_color: bool) -> Vec<Gadget>
{
    */
fn thread_worker(section: &Section, cpu: Arc<dyn cpu::Cpu>, use_color: bool) -> Vec<Gadget>
{

    let engine = DisassemblyEngine::new(DisassemblyEngineType::Capstone, cpu.as_ref());
    debug!("using engine: {}", &engine);
    let gadgets = process_section(&engine, section, cpu, use_color).unwrap();
    debug!("in {} - {} gadget(s) found", section.name.green().bold(), gadgets.len());
    gadgets
    //info!("{:?} is running", thread::current().id());
    //let g: Vec<Gadget> = Vec::new();
    //g
}


fn process_section(engine: &DisassemblyEngine, section: &Section, cpu: Arc<dyn cpu::Cpu>, use_color: bool) -> GenericResult<Vec<Gadget>>
{
    let mut gadgets: Vec<Gadget> = Vec::new();

    for initial_position in get_all_return_positions(&cpu, section)?
    {
        trace!("[{}] {:x} data[..{:x}]", section.name, section.start_address, initial_position);

        let res = find_gadgets_from_position(
            engine,
            section,
            initial_position,
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
