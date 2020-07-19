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
    pub cpu: Option<Box<dyn cpu::Cpu>>,
    pub entry_point_address: u64,
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
    // the info need to build & store the ropgadgets
    //
    pub sections: Option<Vec<Section>>,
    pub gadgets: Vec<Gadget>,
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
                println!("setting verbosity to {}", cnt);

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


        let output_file = match matches.value_of("outfile")
        {
            Some(x) =>
            {
                Some(x.to_string())
            }
            None =>
            {
                None
            }
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
            None => { panic!("unknown") }
        };

        //
        // if the --arch option is given, the user tries to force the format
        //
        let cpu: Option<Box<dyn cpu::Cpu>> = match matches.value_of("arch")
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
                    entry_point_address: 0,
                },
                sections: None,
                gadgets: Vec::new(),
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
            Some(x) => { x.cpu_type() }
            None => { cpu::CpuType::Unknown }
        };

        f.debug_struct("Session")
            .field("path", &self.filepath)
            .field("format", &Some(self.info.format.as_ref()))
            .field("cpu", &Some(cpu))
            .finish()
    }
}