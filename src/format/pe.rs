use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use goblin;
use log::debug;

use crate::cpu;
use crate::{format::Format, section::Permission, section::Section};

use super::ExecutableFormat;

#[derive(Debug)]
pub struct Pe {
    path: PathBuf,
    sections: Vec<Section>,
    cpu: Box<dyn cpu::Cpu>,
    entry_point: u64,
}

impl Pe {
    pub fn new(path: PathBuf, obj: goblin::pe::PE) -> Self {
        let mut executable_sections: Vec<Section> = Vec::new();

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(file);

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

            section.name = section_name;

            let mut perm = Permission::EXECUTABLE;
            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
                perm |= Permission::READABLE;
            }

            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
                perm |= Permission::WRITABLE;
            }

            section.permission = perm;

            reader
                .seek(SeekFrom::Start(s.pointer_to_raw_data as u64))
                .unwrap();
            reader.read_exact(&mut section.data).unwrap();

            debug!("Adding {}", section);
            executable_sections.push(section);
        }

        let cpu: Box<dyn cpu::Cpu> = match obj.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86 => Box::new(cpu::x86::X86 {}),
            goblin::pe::header::COFF_MACHINE_X86_64 => Box::new(cpu::x86::X64 {}),
            goblin::pe::header::COFF_MACHINE_ARM => Box::new(cpu::arm::Arm {}),
            goblin::pe::header::COFF_MACHINE_ARMNT => Box::new(cpu::arm::Arm {}),
            goblin::pe::header::COFF_MACHINE_ARM64 => Box::new(cpu::arm::Arm64 {}),
            _ => {
                panic!("PE is corrupted")
            }
        };

        Self {
            path: path.clone(),
            sections: executable_sections,
            cpu: cpu,
            entry_point: obj.entry as u64,
        }
    }
}

impl ExecutableFormat for Pe {
    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn format(&self) -> Format {
        Format::Pe
    }

    fn sections(&self) -> &Vec<Section> {
        &self.sections
    }

    fn cpu(&self) -> &dyn cpu::Cpu {
        self.cpu.as_ref()
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }
}
