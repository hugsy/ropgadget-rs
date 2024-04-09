pub mod elf;
pub mod mach;
pub mod pe;

use crate::{
    common::GenericResult,
    cpu::{self, CpuType},
    error::Error,
    section::Section,
};

// use clap::ValueEnum;
// use goblin::Object;

#[derive(std::fmt::Debug, Clone /* PartialEq, Eq, PartialOrd, Ord, ValueEnum*/)]
pub enum FileFormat {
    // #[default]
    // Auto,
    // Pe,
    Pe(pe::Pe),
    Elf(elf::Elf),
    // MachO,
    // todo: Raw,
}

impl FileFormat {
    pub fn parse(buf: Vec<u8>) -> GenericResult<FileFormat> {
        match buf.get(0..4) {
            Some(magic) => {
                if &magic[0..pe::IMAGE_DOS_SIGNATURE.len()] == pe::IMAGE_DOS_SIGNATURE {
                    Ok(FileFormat::Pe(pe::Pe::from(buf)))
                } else if &magic[0..elf::ELF_HEADER_MAGIC.len()] == elf::ELF_HEADER_MAGIC {
                    Ok(FileFormat::Elf(elf::Elf::from(buf)))
                // } else if &magic[0..mach::MACHO_HEADER_MAGIC32.len()] == mach::MACHO_HEADER_MAGIC32
                //     || &magic[0..mach::MACHO_HEADER_MAGIC64.len()] == mach::MACHO_HEADER_MAGIC64
                // {
                //     Ok(FileFormat::MachO)
                } else {
                    Err(Error::InvalidMagicParsingError)
                }
            }
            None => Err(Error::InvalidFileError),
        }
    }
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

/// Trait specific to executable files

pub trait ExecutableFileFormat: Send + Sync {
    // fn path(&self) -> &PathBuf;

    fn format(&self) -> &str;

    fn executable_sections(&self) -> Vec<Section>;
    // fn executable_sections(&self) -> dyn Iterator<Item = Section>;

    fn cpu_type(&self) -> CpuType;

    fn entry_point(&self) -> u64;

    fn cpu(&self) -> Box<dyn cpu::Cpu> {
        match self.cpu_type() {
            CpuType::X86 => Box::new(cpu::x86::X86 {}),
            CpuType::X64 => Box::new(cpu::x86::X64 {}),
            CpuType::ARM => Box::new(cpu::arm::Arm {}),
            CpuType::ARM64 => Box::new(cpu::arm::Arm64 {}),
            _ => panic!("CPU type is invalid"),
        }
    }
}

impl std::fmt::Display for dyn ExecutableFileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl std::fmt::Debug for dyn ExecutableFileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableFileFormat")
            .field("format", &self.format().to_string())
            .field("executable_sections", &self.executable_sections().len())
            .field("cpu_type", &self.cpu_type())
            .field("entry_point", &self.entry_point())
            .finish()
    }
}

pub struct SectionIterator<'a, T> {
    index: usize,
    obj: &'a T,
}
