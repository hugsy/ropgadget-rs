pub mod elf;
pub mod mach;
pub mod pe;

use std::{fs, path::PathBuf};

use crate::{common::GenericResult, cpu::CpuType, error::Error, section::Section};

use clap::ValueEnum;
use goblin::Object;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
pub enum FileFormat {
    #[default]
    Auto,
    Pe,
    Elf,
    MachO,
    // todo: Raw,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = match self {
            FileFormat::Pe => "PE",
            FileFormat::Elf => "ELF",
            FileFormat::MachO => "MachO",
            _ => panic!("Invalid FileFormat"),
        };

        write!(f, "BinaryFormat={}", val)
    }
}

/// Trait specific to executable files
pub trait ExecutableFileFormat: Send + Sync {
    fn path(&self) -> &PathBuf;

    fn format(&self) -> FileFormat;

    fn sections(&self) -> &Vec<Section>;

    // fn cpu(&self) -> &dyn cpu::Cpu;

    fn cpu_type(&self) -> CpuType;

    fn entry_point(&self) -> u64;
}

/// Attempt to determine the file
pub fn guess_file_format(file: &PathBuf) -> GenericResult<Box<dyn ExecutableFileFormat>> {
    if !file.as_path().exists() {
        return Err(Error::InvalidFileError);
    }

    let buffer = match fs::read(file.as_path()) {
        Ok(buf) => buf,
        Err(_) => return Err(Error::InvalidFileError),
    };

    let parsed = match Object::parse(&buffer) {
        Ok(e) => e,
        Err(_) => return Err(Error::InvalidFileError),
    };

    match parsed {
        Object::PE(obj) => Ok(Box::new(pe::Pe::new(file.to_path_buf(), obj))),
        Object::Elf(obj) => Ok(Box::new(elf::Elf::new(file.to_path_buf(), obj))),
        Object::Mach(obj) => Ok(Box::new(mach::Mach::new(file.to_path_buf(), obj))),
        Object::Archive(_) => Err(Error::InvalidFileError),
        Object::Unknown(_) => Err(Error::InvalidFileError),
        _ => Err(Error::InvalidFileError),
    }
}
