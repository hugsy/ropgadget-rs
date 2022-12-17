pub mod elf;
pub mod mach;
pub mod pe;

use crate::{common::GenericResult, section::Section};

use clap::ValueEnum;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    Pe,
    Elf,
    Mach,
    // todo: Raw,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::Mach => "Mach",
        };

        write!(f, "BinaryFormat={}", val)
    }
}

pub trait ExecutableFormat {
    type Fmt;

    fn collect_executable_sections(
        &self,
        path: &std::path::PathBuf,
        exec: &Self::Fmt,
    ) -> GenericResult<Vec<Section>>;
}
