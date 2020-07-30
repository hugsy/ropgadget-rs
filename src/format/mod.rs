pub mod pe;
pub mod elf;
pub mod mach;

use crate::{section::Section, common::GenericResult};

#[derive(Debug)]
pub enum Format
{
    Pe,
    Elf,
    Mach,
    // todo: Raw,
}


impl std::fmt::Display for Format
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let val = match self
        {
            Format::Pe => { "PE" }
            Format::Elf => { "ELF" }
            Format::Mach => { "Mach" }
        };

        write!(f, "OS={}", val)
    }
}


pub trait ExecutableFormat
{
    type Fmt;

    fn collect_executable_sections(&self, path: &str, exec: &Self::Fmt) -> GenericResult<Vec<Section>>;
}