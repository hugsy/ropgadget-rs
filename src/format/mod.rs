pub mod elf;
pub mod mach;
pub mod pe;

use std::{fs, path::PathBuf};

use crate::{common::GenericResult, cpu::CpuType, error::Error, section::Section};

use clap::ValueEnum;
// use goblin::Object;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum FileFormat {
    // #[default]
    // Auto,
    Pe,
    Elf,
    MachO,
    // todo: Raw,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // let val = match self {
        //     FileFormat::Pe => "PE",
        //     FileFormat::Elf => "ELF",
        //     FileFormat::MachO => "MachO",
        //     // _ => panic!("Invalid FileFormat"),
        // };

        write!(f, "{:?}", &self)
    }
}

/// Trait specific to executable files
pub trait ExecutableFileFormat: Send + Sync {
    // fn path(&self) -> &PathBuf;

    fn format(&self) -> FileFormat;

    fn executable_sections(&self) -> &Vec<Section>;

    // fn cpu(&self) -> &dyn cpu::Cpu;

    fn cpu_type(&self) -> CpuType;

    fn entry_point(&self) -> u64;
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

/// Attempt to determine the file
pub fn guess_file_format(file: &PathBuf) -> GenericResult<Box<dyn ExecutableFileFormat>> {
    if !file.as_path().exists() {
        return Err(Error::InvalidFileError);
    }

    let buffer = fs::read(file.as_path())?;
    // let parsed = match Object::parse(&buffer) {
    //     Ok(e) => e,
    //     Err(_) => return Err(Error::InvalidFileError),
    // };

    match try_parse(&buffer)? {
        // Object::PE(_) => Ok(Box::new(pe::Pe::new(file.to_path_buf())?)),
        FileFormat::Pe => Ok(Box::new(pe::Pe::new(&buffer)?)),
        // Object::Elf(obj) => Ok(Box::new(elf::Elf::new(file.to_path_buf(), obj))),
        // Object::Mach(obj) => Ok(Box::new(mach::Mach::new(file.to_path_buf(), obj))),
        // Object::Archive(_) => Err(Error::InvalidFileError),
        // Object::Unknown(_) => Err(Error::InvalidFileError),
        _ => Err(Error::InvalidFileError),
    }
}

pub fn try_parse(buf: &[u8]) -> GenericResult<FileFormat> {
    match buf.get(0..4) {
        Some(magic) => {
            if &magic[0..pe::IMAGE_DOS_SIGNATURE.len()] == pe::IMAGE_DOS_SIGNATURE {
                Ok(FileFormat::Pe)
            } else if &magic[0..elf::ELF_HEADER_MAGIC.len()] == elf::ELF_HEADER_MAGIC {
                Ok(FileFormat::Elf)
            } else if &magic[0..mach::MACHO_HEADER_MAGIC.len()] == mach::MACHO_HEADER_MAGIC {
                Ok(FileFormat::MachO)
            } else {
                Err(Error::InvalidMagicParsingError)
            }
        }
        None => Err(Error::InvalidFileError),
    }
}
