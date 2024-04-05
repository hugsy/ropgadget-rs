use colored::Colorize;
use goblin;
use log::debug;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::common::GenericResult;
use crate::cpu::{self, CpuType};
use crate::error;
use crate::section::Permission;
use crate::{format::FileFormat, section::Section};

use super::ExecutableFileFormat;

pub const ELF_HEADER_MAGIC: &[u8] = b"\x7fELF";
pub const ELF_CLASS_32: u8 = 1;
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_TYPE_EXEC: u8 = 2;
pub const ELF_TYPE_DYN: u8 = 3;
pub const ELF_MACHINE_386: u16 = 3;
pub const ELF_MACHINE_ARM: u16 = 40;
pub const ELF_MACHINE_AMD64: u16 = 62;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ElfIdentHeader {
    ei_magic: u32,
    ei_class: u8,
    ei_data: u8,
    ei_version: u8,
    ei_padd: u8,
    ei_padd4: u32,
    ei_padd8: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ElfHeader64 {
    e_ident: ElfIdentHeader,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[derive(Default, Debug)]
pub struct ElfParser<'a> {
    bytes: &'a [u8],
    machine: CpuType,
    number_of_sections: usize,
    section_table_offset: usize,
    image_base: u64,
    pub entry_point: u64,
}

impl<'a> ElfParser<'a> {
    pub fn parse(bytes: &'a [u8]) -> GenericResult<Self> {
        let elf_header: &[u8] = bytes.as_ref();

        match elf_header.get(0..ELF_HEADER_MAGIC.len()) {
            Some(ELF_HEADER_MAGIC) => {}
            _ => return Err(error::Error::InvalidMagicParsingError),
        };

        let is_64b = match elf_header.get(5) {
            Some(val) => match *val {
                ELF_CLASS_32 => false,
                ELF_CLASS_64 => true,
                _ => {
                    return Err(error::Error::InvalidFileError);
                }
            },
            None => {
                return Err(error::Error::InvalidFileError);
            }
        };

        let machine = {
            let machine = {
                let mut dst = [0u8; 2];
                dst.clone_from_slice(elf_header.get(18..20).unwrap());
                u16::from_le_bytes(dst)
            };

            match machine {
                ELF_MACHINE_386 => Ok(cpu::CpuType::X86),
                ELF_MACHINE_AMD64 => Ok(cpu::CpuType::X64),
                ELF_MACHINE_ARM => match is_64b {
                    true => Ok(cpu::CpuType::ARM64),
                    false => Ok(cpu::CpuType::ARM),
                },

                _ => Err(error::Error::UnsupportedCpuError),
            }
        }?;

        Ok(ElfParser {
            bytes: elf_header,
            machine: machine,
            number_of_sections: todo!(),
            image_base: todo!(),
            entry_point: todo!(),
            section_table_offset: todo!(),
        })
    }
}

#[derive(Debug)]
pub struct Elf {
    // path: PathBuf,
    sections: Vec<Section>,
    // cpu: Box<dyn cpu::Cpu>,
    cpu_type: cpu::CpuType,
    entry_point: u64,
}

impl Elf {
    pub fn new(path: PathBuf, obj: goblin::elf::Elf) -> Self {
        let filepath = path.to_str().unwrap();

        let mut executable_sections: Vec<Section> = Vec::new();
        debug!(
            "looking for executable sections in ELF: '{}'",
            filepath.bold()
        );

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(file);

        for current_section in &obj.section_headers {
            // trace!("Testing section {:?}", s);

            // //
            // // disregard non executable section
            // //
            // if !s.is_executable() {
            //     continue;
            // }

            // debug!("Importing section {:?}", s);

            // let mut section = Section::from(s);
            // section.name = Some(String::from(&obj.shdr_strtab[s.sh_name]));

            let mut sect =
                Section::from(current_section).name(&obj.shdr_strtab[current_section.sh_name]);

            if !sect.permission.contains(Permission::EXECUTABLE) {
                continue;
            }

            if reader
                .seek(SeekFrom::Start(current_section.sh_addr))
                .is_err()
            {
                panic!("Invalid offset {}", current_section.sh_addr,)
            }

            match reader.read_exact(&mut sect.data) {
                Ok(_) => {}
                Err(e) => panic!(
                    "Failed to extract section '{}' (size={:#x}) at offset {:#x}: {:?}",
                    &sect.name.clone().unwrap_or_default(),
                    &sect.size(),
                    sect.start_address,
                    e
                ),
            };

            debug!("Adding {}", sect);
            executable_sections.push(sect);
        }

        // let cpu_type = match obj.header.e_machine {
        //     goblin::elf::header::EM_386 => cpu::CpuType::X86,
        //     goblin::elf::header::EM_X86_64 => cpu::CpuType::X64,
        //     goblin::elf::header::EM_ARM => cpu::CpuType::ARM,
        //     goblin::elf::header::EM_AARCH64 => cpu::CpuType::ARM64,
        //     _ => {
        //         panic!("ELF machine format is unsupported")
        //     }
        // };

        Self {
            // path: path.clone(),
            sections: executable_sections,
            cpu_type: cpu::CpuType::from(&obj.header),
            entry_point: obj.entry,
        }
    }
}

impl ExecutableFileFormat for Elf {
    // fn path(&self) -> &PathBuf {
    //     &self.path
    // }

    fn format(&self) -> FileFormat {
        FileFormat::Elf
    }

    fn executable_sections(&self) -> &Vec<Section> {
        &self.sections
    }

    // fn cpu(&self) -> &dyn cpu::Cpu {
    //     self.cpu.as_ref()
    // }

    fn cpu_type(&self) -> cpu::CpuType {
        self.cpu_type
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }
}
