pub mod elf;
pub mod mach;
pub mod pe;

use std::{fs, path::PathBuf};

use crate::{common::GenericResult, cpu, error::Error, section::Section};

use clap::ValueEnum;
use goblin::Object;

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

/// Trait specific to executable files
pub trait ExecutableFormat: Send + Sync {
    fn path(&self) -> &PathBuf;

    fn format(&self) -> Format;

    fn sections(&self) -> &Vec<Section>;

    fn cpu(&self) -> &dyn cpu::Cpu;

    fn entry_point(&self) -> u64;
}

/// Attempt to determine the file
pub fn guess_file_format(file: &PathBuf) -> GenericResult<Box<dyn ExecutableFormat>> {
    if !file.as_path().exists() {
        return Err(Error::InvalidFileError);
    }

    let buffer = match fs::read(file.as_path()) {
        Ok(buf) => buf,
        Err(_) => return Err(Error::InvalidFileError),
    };

    match Object::parse(&buffer).unwrap() {
        Object::PE(obj) => Ok(Box::new(pe::Pe::new(file.to_path_buf(), obj))),
        Object::Elf(obj) => Ok(Box::new(elf::Elf::new(file.to_path_buf(), obj))),
        Object::Mach(obj) => Ok(Box::new(mach::Mach::new(file.to_path_buf(), obj))),
        Object::Archive(_) => Err(Error::InvalidFileError),
        Object::Unknown(_) => Err(Error::InvalidFileError),
    }
}
