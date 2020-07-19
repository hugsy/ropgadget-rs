pub mod pe;
pub mod elf;
pub mod mach;

use crate::{section::Section, common::GenericResult};

#[derive(Debug)]
pub enum Format
{
    Pe,
    Elf,
    // todo: Macho, Raw,
}


pub trait ExecutableFormat
{
    type Fmt;

    fn collect_executable_sections(&self, path: &str, exec: &Self::Fmt) -> GenericResult<Vec<Section>>;
}