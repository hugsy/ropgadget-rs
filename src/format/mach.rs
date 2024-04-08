// use std::fs::File;
// use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use colored::Colorize;
use goblin;
use log::debug;

use crate::cpu;
use crate::{format::FileFormat, section::Permission, section::Section};

use super::ExecutableFileFormat;

pub const MACHO_HEADER_MAGIC32: &[u8] = b"\xce\xfa\xed\xfe"; // 0xfeedface
pub const MACHO_HEADER_MAGIC64: &[u8] = b"\xcf\xfa\xed\xfe"; // 0xfeedfacf

pub const MACHO_MACHINE_X86: u32 = 0x00000007;
pub const MACHO_MACHINE_ARM: u32 = 0x0000000C;

pub const MACHO_FILETYPE_RELOC: u32 = 0x00000001;
pub const MACHO_FILETYPE_EXEC: u32 = 0x00000005;
pub const MACHO_FILETYPE_DYLIB: u32 = 0x00000006;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MachOHeader {
    magic: u32,
    cpu_type: u32,
    cpu_subtype: u32,
    file_type: u32,
    load_command_num: u32,
    load_command_sz: u32,
    flags: u32,
    // reserved: u32,
}

pub struct Mach {
    // path: PathBuf,
    // sections: Vec<Section>,
    // cpu_type: cpu::CpuType,
    // entry_point: u64,
}
// impl Mach {
//     pub fn new(path: PathBuf, obj: goblin::mach::Mach) -> Self {
//         let bin = match obj {
//             goblin::mach::Mach::Binary(macho) => macho,
//             goblin::mach::Mach::Fat(_) => todo!(),
//         };

//         let filepath = path.to_str().unwrap();

//         let mut executable_sections: Vec<Section> = Vec::new();

//         debug!(
//             "looking for executables sections in MachO: '{}'",
//             filepath.bold()
//         );

//         for current_segment in &bin.segments {
//             // for current_section in current_segment.sections().iter() {
//             // if s.flags & constants::S_ATTR_PURE_INSTRUCTIONS == 0
//             //     || s.flags & constants::S_ATTR_SOME_INSTRUCTIONS == 0
//             // {
//             //     continue;
//             // }

//             // let section_name = match std::str::from_utf8(&s.segname) {
//             //     Ok(v) => String::from(v).replace("\0", ""),
//             //     Err(_) => "".to_string(),
//             // };

//             // let mut section = Section::new(s.vmaddr as u64, (s.vmaddr + s.vmsize - 1) as u64);

//             // section.name = Some(section_name);

//             // let perm = Permission::EXECUTABLE | Permission::READABLE; // todo: fix later
//             // section.permission = perm;

//             let section = Section::from(current_segment).data(current_segment.data.to_vec());

//             if !section.permission.contains(Permission::EXECUTABLE) {
//                 continue;
//             }

//             // reader
//             //     .seek(SeekFrom::Start(current_segment.fileoff as u64))
//             //     .unwrap();
//             // reader.read_exact(&mut section.data).unwrap();

//             debug!("Adding {}", section);
//             executable_sections.push(section);
//             // }
//         }

//         // let cpu_type = match bin.header.cputype {
//         //     constants::cputype::CPU_TYPE_X86 => cpu::CpuType::X86,
//         //     constants::cputype::CPU_TYPE_X86_64 => cpu::CpuType::X64,
//         //     constants::cputype::CPU_TYPE_ARM => cpu::CpuType::ARM,
//         //     constants::cputype::CPU_TYPE_ARM64 => cpu::CpuType::ARM64,
//         //     _ => {
//         //         panic!("MachO is corrupted")
//         //     }
//         // };

//         Self {
//             // path: path.clone(),
//             sections: executable_sections,
//             cpu_type: cpu::CpuType::from(&bin.header),
//             entry_point: bin.entry,
//         }
//     }
// }

// impl ExecutableFileFormat for Mach {
//     // fn path(&self) -> &PathBuf {
//     //     &self.path
//     // }

//     fn format(&self) -> FileFormat {
//         FileFormat::MachO
//     }

//     fn executable_sections(&self) -> &Vec<Section> {
//         &self.sections
//     }

//     // fn cpu(&self) -> &dyn cpu::Cpu {
//     //     self.cpu.as_ref()
//     // }

//     fn cpu_type(&self) -> cpu::CpuType {
//         self.cpu_type
//     }

//     fn entry_point(&self) -> u64 {
//         self.entry_point
//     }
// }
