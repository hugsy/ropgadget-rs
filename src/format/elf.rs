// use colored::Colorize;
// use goblin;

use std::convert::TryInto;
// use std::fs::File;
// use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem;
// use std::path::PathBuf;

use crate::common::GenericResult;
use crate::cpu::{self};
use crate::error;
use crate::section::Permission;
use crate::{format::FileFormat, section::Section};

use super::{ExecutableFileFormat, SectionIterator};

pub const ELF_HEADER_MAGIC: &[u8] = b"\x7fELF";
pub const ELF_CLASS_32: u8 = 1;
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_TYPE_EXEC: u8 = 2;
pub const ELF_TYPE_DYN: u8 = 3;
pub const ELF_MACHINE_386: u16 = 0x0003;
pub const ELF_MACHINE_ARM: u16 = 0x0028;
pub const ELF_MACHINE_AMD64: u16 = 0x003e;
pub const ELF_SECTION_FLAGS_WRITE: u64 = 0x01;
pub const ELF_SECTION_FLAGS_EXECINSTR: u64 = 0x04;

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
struct ElfHeader32 {
    e_ident: ElfIdentHeader,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
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
struct ElfSectionHeader64 {
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

type ElfSectionIterator<'a> = SectionIterator<'a, Elf>;

pub type ElfCharacteristics = u64;

impl<'a> Iterator for ElfSectionIterator<'a> {
    type Item = Section;

    fn next(&mut self) -> Option<Self::Item> {
        let elf_header = &self.obj.bytes;
        let section_size: usize = mem::size_of::<ElfSectionHeader64>();

        if self.index >= self.obj.number_of_sections {
            return None;
        }

        let index = self.index.checked_mul(section_size)?;
        self.index += 1;

        let current_section =
            elf_header.get(self.obj.section_table_offset.checked_add(index)?..)?;

        // TODO 32b
        let start_address = u64::from_le_bytes(current_section[0x10..0x18].try_into().unwrap());
        let section_size =
            u64::from_le_bytes(current_section[0x20..0x28].try_into().unwrap()) as usize;
        let section_name = String::from_utf8(current_section[0..4].to_vec()).unwrap();
        let flags = u64::from_le_bytes(current_section[0x8..0x10].try_into().unwrap())
            as ElfCharacteristics;

        let raw_offset =
            u64::from_le_bytes(current_section[0x18..0x20].try_into().unwrap()) as usize;

        Some(Section {
            start_address,
            end_address: start_address.checked_add(section_size as u64)?,
            name: Some(section_name),
            permission: Permission::from(flags),
            data: elf_header[raw_offset..raw_offset + section_size].into(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct Elf {
    // // path: PathBuf,
    // sections: Vec<Section>,
    // // cpu: Box<dyn cpu::Cpu>,
    // cpu_type: cpu::CpuType,
    // entry_point: u64,
    cpu_type: cpu::CpuType,
    bytes: Vec<u8>,
    number_of_sections: usize,
    section_table_offset: usize,
    entry_point: u64,
    // image_base: u64,
}

impl Elf {
    pub fn new(bytes: Vec<u8>) -> GenericResult<Self> {
        let elf_header: &[u8] = bytes.as_ref();

        match elf_header.get(0..ELF_HEADER_MAGIC.len()) {
            Some(ELF_HEADER_MAGIC) => {}
            _ => return Err(error::Error::InvalidMagicParsingError),
        };

        let is_64b = {
            let ei_class_off = mem::offset_of!(ElfIdentHeader, ei_class);
            match elf_header.get(ei_class_off) {
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
            }
        };

        let machine = {
            let ei_class_off = mem::offset_of!(ElfHeader64, e_machine);
            let machine = {
                let mut dst = [0u8; 2];
                dst.clone_from_slice(elf_header.get(ei_class_off..ei_class_off + 2).unwrap());
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

        let entrypoint = {
            match is_64b {
                true => {
                    let e_entry_off = mem::offset_of!(ElfHeader64, e_entry);
                    u64::from_le_bytes(elf_header[e_entry_off..e_entry_off + 8].try_into().unwrap())
                }
                false => {
                    let e_entry_off = mem::offset_of!(ElfHeader32, e_entry);
                    u32::from_le_bytes(elf_header[e_entry_off..e_entry_off + 4].try_into().unwrap())
                        as u64
                }
            }
        };

        let number_of_sections = {
            let e_shnum_off = match is_64b {
                true => mem::offset_of!(ElfHeader64, e_shnum),
                false => mem::offset_of!(ElfHeader32, e_shnum),
            };
            u16::from_le_bytes(elf_header[e_shnum_off..e_shnum_off + 2].try_into().unwrap())
        } as usize;

        let section_table_offset = {
            match is_64b {
                true => {
                    let e_shoff_off = mem::offset_of!(ElfHeader64, e_shoff);
                    u64::from_le_bytes(elf_header[e_shoff_off..e_shoff_off + 8].try_into().unwrap())
                        as usize
                }
                false => {
                    let e_shoff_off = mem::offset_of!(ElfHeader32, e_shoff);
                    u32::from_le_bytes(elf_header[e_shoff_off..e_shoff_off + 4].try_into().unwrap())
                        as usize
                }
            }
        };

        Ok(Self {
            // path: path.clone(),
            // sections: executable_sections,
            // cpu_type: elf.machine,
            // entry_point: elf.entry_point,
            bytes,
            cpu_type: machine,
            number_of_sections,
            section_table_offset,
            // image_base: 0,
            entry_point: entrypoint,
        })
    }
}

impl From<Vec<u8>> for Elf {
    fn from(buffer: Vec<u8>) -> Self {
        Elf::new(buffer).expect("Failed to parse bytes")
    }
}

impl ExecutableFileFormat for Elf {
    // fn path(&self) -> &PathBuf {
    //     &self.path
    // }

    fn format(&self) -> &str {
        "ELF"
    }

    fn executable_sections(&self) -> Vec<Section> {
        ElfSectionIterator {
            index: 0,
            obj: self,
        }
        .collect()
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
