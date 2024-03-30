use std::path::PathBuf;

use clap::{ArgAction, Parser};
use log::{info, LevelFilter};

use ropgadget_rs::common::GenericResult;
use ropgadget_rs::cpu;

use ropgadget_rs::collect_all_gadgets;
use ropgadget_rs::gadget::InstructionGroup;
use ropgadget_rs::session::RopGadgetOutput;
use ropgadget_rs::session::{RopProfileStrategy, Session};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)] // Read from `Cargo.toml`
pub struct Args {
    /// The file to parse
    #[arg(value_name = "FILE")]
    filepath: PathBuf,

    /// The number of threads to use
    #[arg(short, long = "number-of-threads", default_value_t = 4)]
    thread_num: u8,

    /// Write gadget to file (optional, defaults to stdout)
    #[arg(short, long = "output-file", value_name = "OUTPUT")]
    output_file: Option<PathBuf>,

    /// The verbosity level
    #[arg(short, long = "verbose", default_value_t = 2)]
    verbosity: u8,

    /// Unique gadgets
    #[arg(short, long, action = ArgAction::SetTrue)]
    unique: bool,

    /// Force the architecture to given value
    #[arg(long, value_enum)]
    architecture: Option<cpu::CpuType>,

    // /// Force the OS to given value
    // #[arg(long, value_enum, default_value_t = format::FileFormat::Auto)]
    // format: Option<format::FileFormat>,
    /// Specify an image base
    #[arg(short, long, default_value_t = 0)]
    image_base: u32,

    /// Disable colors on output. This option is forced on when writing to file.
    #[arg(long)]
    no_color: bool,

    /// The maximum number of instructions in a gadget
    #[arg(long, default_value_t = 6)]
    max_insn_per_gadget: u8,

    /// The maximum size of the gadget
    #[arg(long, default_value_t = 32)]
    max_size: u8,

    /// The type of gadgets to focus on (default - return only)
    #[arg(long, value_enum)]
    rop_types: Vec<InstructionGroup>,

    /// The profile type (default - fast)
    #[arg(long, value_enum, default_value_t = RopProfileStrategy::Fast)]
    profile_type: RopProfileStrategy,
}

fn main() -> GenericResult<()> {
    let args = Args::parse();

    let verbosity = match args.verbosity {
        4 => LevelFilter::Trace, // -vvvv
        3 => LevelFilter::Debug, // -vvv
        2 => LevelFilter::Info,  // -vv
        1 => LevelFilter::Warn,  // -v
        _ => LevelFilter::Error,
    };

    let _output = match args.output_file {
        None => RopGadgetOutput::Console,
        Some(fpath) => RopGadgetOutput::File(fpath),
    };

    let sess = Session::new(args.filepath)
        .nb_thread(args.thread_num.into())
        .output(_output)
        .unique_only(args.unique)
        .verbosity(verbosity)
        .use_color(!args.no_color);

    info!("Created session: {}", sess);
    collect_all_gadgets(sess)
}
