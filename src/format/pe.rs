use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use goblin;
use log::debug;

use crate::cpu;
// use crate::cpu;
use crate::{format::FileFormat, section::Permission, section::Section};

use super::ExecutableFileFormat;

#[derive(Debug)]
pub struct Pe {
    path: PathBuf,
    pub sections: Vec<Section>,
    // cpu: Box<dyn cpu::Cpu>,
    pub entry_point: u64,

    cpu_type: cpu::CpuType,
}

impl Default for Pe {
    fn default() -> Self {
        Self {
            path: Default::default(),
            sections: Default::default(),
            entry_point: Default::default(),
            cpu_type: Default::default(),
        }
    }
}

impl From<goblin::pe::PE<'_>> for Pe {
    fn from(obj: goblin::pe::PE) -> Self {
        let mut executable_sections: Vec<Section> = Vec::new();

        // let file = File::open(&path).unwrap();
        // let mut reader = BufReader::new(file);

        for s in &obj.sections {
            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }

            let section_name = match std::str::from_utf8(&s.name) {
                Ok(v) => String::from(v).replace("\0", ""),
                Err(_) => String::new(),
            };

            let mut section = Section::new(
                s.virtual_address as u64,
                (s.virtual_address + s.virtual_size - 1) as u64,
            );

            section.name = Some(section_name);

            let mut perm = Permission::EXECUTABLE;
            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
                perm |= Permission::READABLE;
            }

            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
                perm |= Permission::WRITABLE;
            }

            section.permission = perm;

            // let data = s.data();

            // reader
            //     .seek(SeekFrom::Start(s.pointer_to_raw_data as u64))
            //     .unwrap();
            // reader.read_exact(&mut section.data).unwrap();

            // debug!("Adding {}", section);
            // executable_sections.push(section);
        }

        let _cpu_type = match obj.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => cpu::CpuType::X86,
            goblin::pe::header::COFF_MACHINE_X86_64 => cpu::CpuType::X64,
            goblin::pe::header::COFF_MACHINE_ARM => cpu::CpuType::ARM,
            goblin::pe::header::COFF_MACHINE_ARMNT => cpu::CpuType::ARM,
            goblin::pe::header::COFF_MACHINE_ARM64 => cpu::CpuType::ARM64,
            _ => {
                panic!("PE is corrupted")
            }
        };

        Self {
            // path: Default::default(),
            sections: executable_sections,
            // cpu,
            cpu_type: _cpu_type,
            entry_point: obj.entry as u64,
            ..Default::default()
        }
    }
}

impl ExecutableFileFormat for Pe {
    fn path(&self) -> &PathBuf {
        &self.path
    }

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
