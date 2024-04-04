///!
///! Basic implementation of a PE parser, supports x86/64 to extract quickly the sections
///!
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::{fmt, mem};

// use goblin;
use log::debug;

use crate::common::GenericResult;
use crate::cpu::{self, CpuType};
use crate::error::{self};
// use crate::cpu;
use crate::{format::FileFormat, section::Permission, section::Section};

use super::ExecutableFileFormat;

#[derive(Debug, Default)]
pub struct Pe {
    // path: PathBuf,
    pub sections: Vec<Section>,
    // cpu: Box<dyn cpu::Cpu>,
    pub entry_point: u64,
    cpu_type: cpu::CpuType,
}

pub const IMAGE_DOS_SIGNATURE: &[u8] = b"MZ";
pub const IMAGE_NT_SIGNATURE: &[u8] = b"PE\0\0";

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageFileHeader {
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader32 {
    // Standard fields.
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    // NT additional fields.
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    // Standard fields.
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    // NT additional fields.
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

// const IMAGE_DOS_HEADER_SIZE: usize = mem::size_of::<ImageDosHeader>();
const IMAGE_NT_HEADER_SIZE: usize = mem::size_of::<ImageFileHeader>();
// const IMAGE_OPTIONAL_HEADER32_SIZE: usize = mem::size_of::<ImageOptionalHeader32>();
// const IMAGE_OPTIONAL_HEADER64_SIZE: usize = mem::size_of::<ImageOptionalHeader64>();

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_X86_64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

#[derive(Default)]
pub struct PeParser<'a> {
    bytes: &'a [u8],
    machine: CpuType,
    number_of_sections: usize,
    section_table_offset: usize,
    image_base: u64,
    pub entry_point: u64,
}

impl<'a> fmt::Debug for PeParser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeParser [machine={}, number_of_sections={}, section_table_offset={}, image_base={:#x}, entry_point={:#x}]",
            &self.machine, &self.number_of_sections,
            &self.section_table_offset, &self.image_base, &self.entry_point
        )
    }
}

impl<'a> PeParser<'a> {
    ///
    /// Basic PE parser: for now there's no need for a complete parsing, so just parse enough to extract enough info to
    /// reach the sections so we can use the iterator later on
    ///
    pub fn parse(bytes: &'a [u8]) -> GenericResult<Self> {
        let dos_header: &[u8] = bytes.as_ref();

        // check the dos signature
        match dos_header.get(0..2) {
            Some(IMAGE_DOS_SIGNATURE) => {}
            _ => return Err(error::Error::InvalidMagicParsingError),
        };

        // goto the pe header
        let pe_offset = {
            let e_lfanew = mem::offset_of!(ImageDosHeader, e_lfanew);
            let mut dst = [0u8; 4];
            dst.clone_from_slice(&bytes[e_lfanew..e_lfanew.checked_add(4).unwrap()]);
            u32::from_le_bytes(dst)
        } as usize;

        // check for the pe signature
        match dos_header.get(pe_offset..pe_offset.checked_add(4).unwrap()) {
            Some(IMAGE_NT_SIGNATURE) => {}
            _ => return Err(error::Error::InvalidStructureParsingError),
        };

        // slice to the pe header directly
        let pe_header = dos_header.get(pe_offset..).unwrap();

        // check machine id
        let machine = {
            let machine = {
                let mut dst = [0u8; 2];
                dst.clone_from_slice(pe_header.get(4..6).unwrap());
                u16::from_le_bytes(dst)
            };

            match machine {
                IMAGE_FILE_MACHINE_I386 => Ok(cpu::CpuType::X86),
                IMAGE_FILE_MACHINE_X86_64 => Ok(cpu::CpuType::X64),
                IMAGE_FILE_MACHINE_ARM64 => Ok(cpu::CpuType::ARM64),
                _ => Err(error::Error::UnsupportedCpuError),
            }
        }?;

        //
        // get the optional header info we need
        // - number of sections
        // - size
        // - characteristics
        // - the offset to the section table
        //
        let number_of_sections = {
            let number_of_sections = mem::offset_of!(ImageFileHeader, number_of_sections);
            let mut dst = [0u8; 2];
            dst.clone_from_slice(
                pe_header
                    .get(number_of_sections..number_of_sections + 2)
                    .unwrap(),
            );
            u16::from_le_bytes(dst)
        } as usize;

        let size_of_optional_header = {
            let size_of_optional_header = mem::offset_of!(ImageFileHeader, size_of_optional_header);
            let mut dst = [0u8; 2];
            dst.clone_from_slice(
                pe_header
                    .get(size_of_optional_header..size_of_optional_header + 2)
                    .unwrap(),
            );
            u16::from_le_bytes(dst)
        } as usize;

        // let characteristics = {
        //     let characteristics = mem::offset_of!(ImageNtHeader, characteristics);
        //     let mut dst = [0u8; 2];
        //     dst.clone_from_slice(
        //         pe_header
        //             .get(
        //                 pe_offset.checked_add(characteristics).unwrap()
        //                     ..pe_offset.checked_add(characteristics + 2).unwrap(),
        //             )
        //             .unwrap(),
        //     );
        //     u16::from_le_bytes(dst)
        // } as u16;

        let section_table_offset: usize = pe_offset
            .checked_add(IMAGE_NT_HEADER_SIZE)
            .and_then(|x| x.checked_add(size_of_optional_header))
            .unwrap();

        let opt_hdrs = pe_header.get(IMAGE_NT_HEADER_SIZE..).unwrap();
        let image_base_off = match machine {
            cpu::CpuType::X86 => mem::offset_of!(ImageOptionalHeader32, image_base),
            cpu::CpuType::X64 => mem::offset_of!(ImageOptionalHeader64, image_base),
            cpu::CpuType::ARM64 => mem::offset_of!(ImageOptionalHeader64, image_base),
            _ => unreachable!(),
        } as usize;

        let image_base = u32::from_le_bytes(
            opt_hdrs[image_base_off..image_base_off + 4]
                .try_into()
                .unwrap(),
        ) as u64;

        let entry_point_off = match machine {
            cpu::CpuType::X86 => mem::offset_of!(ImageOptionalHeader32, address_of_entry_point),
            cpu::CpuType::X64 => mem::offset_of!(ImageOptionalHeader64, address_of_entry_point),
            cpu::CpuType::ARM64 => mem::offset_of!(ImageOptionalHeader64, address_of_entry_point),
            _ => unreachable!(),
        } as usize;

        let entry_point = u32::from_le_bytes(
            opt_hdrs[entry_point_off..entry_point_off + 4]
                .try_into()
                .unwrap(),
        ) as u64;

        Ok(PeParser {
            bytes: dos_header,
            machine: machine,
            number_of_sections: number_of_sections,
            image_base: image_base,
            entry_point: entry_point,
            section_table_offset,
        })
    }

    pub fn sections(&self) -> GenericResult<Vec<Section>> {
        let mut vec = Vec::<Section>::new();
        let mut si = SectionIterator { index: 0, pe: self };
        loop {
            let res = si.next();
            match res {
                Some(sec) => vec.push(sec),
                None => break,
            }
        }
        Ok(vec)
    }

    // TODO tests
}

pub struct SectionIterator<'a> {
    index: usize,
    pe: &'a PeParser<'a>,
}

pub type PeCharacteristics = u32;

impl<'a> Iterator for SectionIterator<'a> {
    type Item = Section;

    fn next(&mut self) -> Option<Self::Item> {
        let dos_header = self.pe.bytes;
        let section_size: usize = mem::size_of::<ImageSectionHeader>();

        if self.index >= self.pe.number_of_sections {
            return None;
        }

        let section_index = self.index;
        self.index += 1;

        let section_offset = self
            .pe
            .section_table_offset
            .checked_add(section_index * section_size)?;

        let name =
            String::from_utf8(dos_header[section_offset..section_offset + 0x08].to_vec()).unwrap();
        let virtual_size = u32::from_le_bytes(
            dos_header[section_offset + 0x08..section_offset + 0x0c]
                .try_into()
                .unwrap(),
        ) as u64;
        let virtual_address = u32::from_le_bytes(
            dos_header[section_offset + 0x0c..section_offset + 0x10]
                .try_into()
                .unwrap(),
        ) as u64;
        let raw_size = u32::from_le_bytes(
            dos_header[section_offset + 0x10..section_offset + 0x14]
                .try_into()
                .unwrap(),
        ) as usize;
        let raw_offset = u32::from_le_bytes(
            dos_header[section_offset + 0x14..section_offset + 0x18]
                .try_into()
                .unwrap(),
        ) as usize;
        let characteristics = u32::from_le_bytes(
            dos_header[section_offset + 0x24..section_offset + 0x28]
                .try_into()
                .unwrap(),
        ) as PeCharacteristics;

        Some(Section {
            start_address: self.pe.image_base.checked_add(virtual_address)?,
            end_address: self.pe.image_base.checked_add(virtual_address)? + virtual_size,
            name: Some(name),
            permission: Permission::from(characteristics),
            data: dos_header[raw_offset..raw_offset + raw_size].into(),
        })
    }
}

// impl<'a> IntoIterator for PeParser<'a> {
//     type Item = Section;
//     type IntoIter = std::vec::IntoIter<Self::Item>;

//     fn into_iter(self) -> Self::IntoIter {
//         let dos_header = self.bytes;
//         let section_size: usize = mem::size_of::<ImageSectionHeader>();

//         for section_index in 0..self.number_of_sections {
//             println!("parsing {}", section_index);

//             let section_offset = self
//                 .section_table_offset
//                 .checked_add(section_index * section_size)
//                 .unwrap();

//             let name =
//                 String::from_utf8(dos_header[section_offset..section_offset + 0x08].to_vec())
//                     .unwrap();
//             let virtual_size = u32::from_le_bytes(
//                 dos_header[section_offset + 0x08..section_offset + 0x0c]
//                     .try_into()
//                     .unwrap(),
//             ) as u64;
//             let virtual_address = u32::from_le_bytes(
//                 dos_header[section_offset + 0x0c..section_offset + 0x10]
//                     .try_into()
//                     .unwrap(),
//             ) as u64;
//             let raw_size = u32::from_le_bytes(
//                 dos_header[section_offset + 0x10..section_offset + 0x14]
//                     .try_into()
//                     .unwrap(),
//             ) as usize;
//             let raw_offset = u32::from_le_bytes(
//                 dos_header[section_offset + 0x14..section_offset + 0x18]
//                     .try_into()
//                     .unwrap(),
//             ) as usize;
//             let characteristics = u32::from_le_bytes(
//                 dos_header[section_offset + 0x24..section_offset + 0x28]
//                     .try_into()
//                     .unwrap(),
//             ) as PeCharacteristics;

//             return Some(Section {
//                 start_address: self.image_base.checked_add(virtual_address)?,
//                 end_address: self.image_base.checked_add(virtual_address)? + virtual_size,
//                 name: Some(name),
//                 permission: Permission::from(characteristics),
//                 data: dos_header[raw_offset..raw_offset + raw_size].into(),
//             });
//         }

//         None
//     }
// }

impl Pe {
    // pub fn new(path: PathBuf, obj: goblin::pe::PE<'_>) -> Self {
    // pub fn new(path: PathBuf) -> GenericResult<Self> {
    // let mut executable_sections: Vec<Section> = Vec::new();
    // let mut file = File::open(&path)?;
    // let mut buf = Vec::<u8>::new();
    // file.read_to_end(&mut buf)?;

    pub fn new(buf: &[u8]) -> GenericResult<Self> {
        let pe = PeParser::parse(buf)?;
        // let mut reader = BufReader::new(file);
        let entry_point = pe.entry_point;
        let machine = pe.machine;

        debug!("{:?}", &pe);

        // let executable_sections = pe
        //     .filter(|s| s.permission.contains(Permission::EXECUTABLE))
        //     .collect();

        // let section_iter = SectionIterator { index: 0, pe: &pe };

        let executable_sections = pe
            .sections()?
            .into_iter()
            .filter(|s| s.permission.contains(Permission::EXECUTABLE))
            .collect();

        debug!("{:?}", &executable_sections);

        // for current_section in &obj.sections {
        // for section in pe {
        //     // if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE == 0 {
        //     //     continue;
        //     // }

        //     // let section_name = match std::str::from_utf8(&s.name) {
        //     //     Ok(v) => String::from(v).replace("\0", ""),
        //     //     Err(_) => String::new(),
        //     // };

        //     // let mut section = Section::new(
        //     //     s.virtual_address as u64,
        //     //     (s.virtual_address + s.virtual_size - 1) as u64,
        //     // );

        //     // section.name = Some(section_name);

        //     // let mut perm = Permission::EXECUTABLE;
        //     // if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
        //     //     perm |= Permission::READABLE;
        //     // }

        //     // if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
        //     //     perm |= Permission::WRITABLE;
        //     // }

        //     // section.permission = perm;

        //     // let data = s.data();

        //     // let mut section = Section::from(current_section);

        //     if !section.permission.contains(Permission::EXECUTABLE) {
        //         continue;
        //     }

        //     // reader.seek(SeekFrom::Start(current_section.pointer_to_raw_data as u64))?;

        //     // reader.read_exact(&mut section.data).unwrap();

        //     debug!("Adding {}", section);
        //     executable_sections.push(section);
        // }

        Ok(Self {
            // path: path.clone(),
            sections: executable_sections,
            // cpu,
            cpu_type: machine,
            entry_point: entry_point,
            ..Default::default()
        })
    }
}

impl ExecutableFileFormat for Pe {
    // fn path(&self) -> &PathBuf {
    //     &self.path
    // }

    fn format(&self) -> FileFormat {
        FileFormat::Pe
    }

    fn sections(&self) -> &Vec<Section> {
        &self.sections
    }

    // fn cpu(&self) -> &dyn cpu::Cpu {
    //     self.cpu.as_ref()
    // }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }

    fn cpu_type(&self) -> cpu::CpuType {
        self.cpu_type
    }
}
