pub mod elf;
pub mod mach;
pub mod pe;

use std::{fs, path::PathBuf};

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
    Pe,
    Pe2(pe::Pe),
    Elf,
    MachO,
    // todo: Raw,
}

impl FileFormat {
    pub fn parse(buf: Vec<u8>) -> GenericResult<FileFormat> {
        match buf.get(0..4) {
            Some(magic) => {
                if &magic[0..pe::IMAGE_DOS_SIGNATURE.len()] == pe::IMAGE_DOS_SIGNATURE {
                    Ok(FileFormat::Pe2(pe::Pe::from(buf)))
                }
                //  else if &magic[0..elf::ELF_HEADER_MAGIC.len()] == elf::ELF_HEADER_MAGIC {
                //     Ok(FileFormat::Elf)
                // } else if &magic[0..mach::MACHO_HEADER_MAGIC32.len()] == mach::MACHO_HEADER_MAGIC32
                //     || &magic[0..mach::MACHO_HEADER_MAGIC64.len()] == mach::MACHO_HEADER_MAGIC64
                // {
                //     Ok(FileFormat::MachO)
                // }
                else {
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

    fn format(&self) -> FileFormat;

    fn executable_sections(&self) -> Vec<Section>;
    // fn executable_sections(&self) -> dyn Iterator<Item = Section>;

    fn cpu_type(&self) -> CpuType;

    fn entry_point(&self) -> u64;

    fn cpu(&self) -> Box<dyn cpu::Cpu> {
        match self.cpu_type() {
            CpuType::X86 => Box::new(cpu::x86::X86 {}),
            CpuType::X64 => Box::new(cpu::x86::X64 {}),
            CpuType::ARM => Box::new(cpu::arm::Arm64 {}),
            CpuType::ARM64 => Box::new(cpu::arm::Arm {}),
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

// /// Attempt to determine the file
// pub fn guess_file_format(file: &PathBuf) -> GenericResult<Box<dyn ExecutableFileFormat>> {
//     if !file.as_path().exists() {
//         return Err(Error::InvalidFileError);
//     }

//     let buffer = fs::read(file.as_path())?;
//     // let parsed = match Object::parse(&buffer) {
//     //     Ok(e) => e,
//     //     Err(_) => return Err(Error::InvalidFileError),
//     // };

//     match FileFormat::parse(&buffer)? {
//         // Object::PE(_) => Ok(Box::new(pe::Pe::new(file.to_path_buf())?)),
//         FileFormat::Pe2(pe) => Ok(Box::new(pe)),
//         // Object::Elf(obj) => Ok(Box::new(elf::Elf::new(file.to_path_buf(), obj))),
//         // Object::Mach(obj) => Ok(Box::new(mach::Mach::new(file.to_path_buf(), obj))),
//         // Object::Archive(_) => Err(Error::InvalidFileError),
//         // Object::Unknown(_) => Err(Error::InvalidFileError),
//         _ => Err(Error::InvalidFileError),
//     }
// }

pub struct SectionIterator<'a, T> {
    index: usize,
    obj: &'a T,
}

// pub struct Parser<'a> {
//     bytes: &'a [u8],
//     machine: CpuType,
//     number_of_sections: usize,
//     section_table_offset: usize,
//     entry_point: u64,
//     image_base: u64,
// }

// impl<'a, T> std::fmt::Debug for Parser<'a, T> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Parser")
//             .field("machine", &self.machine)
//             .field("number_of_sections", &self.number_of_sections)
//             .field(
//                 "section_table_offset",
//                 &format_args!("{:#x}", &self.section_table_offset),
//             )
//             .field("entry_point", &format_args!("{:#x}", &self.entry_point))
//             .finish()
//     }
// }

// pub trait FileFormatParser<'a> {
//     fn parse(bytes: &'a [u8]) -> GenericResult<Self>
//     where
//         Self: Sized;

//     fn sections(&self) -> GenericResult<Vec<Section>>;
// }
