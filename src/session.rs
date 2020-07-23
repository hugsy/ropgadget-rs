use clap::App;
use colored::*;
use log::{Record, Level, Metadata, LevelFilter};


use crate::format::Format;
use crate::cpu;
use crate::gadget::Gadget;
use crate::section::Section;


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
            None => { 10 }
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