use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use colored::Colorize;
use goblin;
use goblin::mach::constants;
use log::debug;

use crate::cpu;
use crate::{format::Format, section::Permission, section::Section};

use super::ExecutableFormat;

pub struct Mach {
    path: PathBuf,
    sections: Vec<Section>,
    cpu: Box<dyn cpu::Cpu>,
    entry_point: u64,
}
impl Mach {
    pub fn new(path: PathBuf, obj: goblin::mach::Mach) -> Self {
        let bin = match obj {
            goblin::mach::Mach::Fat(_) => {
                todo!()
            }
            goblin::mach::Mach::Binary(macho) => macho,
        };

        let filepath = path.to_str().unwrap();

        let mut sections: Vec<Section> = Vec::new();

        debug!(
            "looking for executables sections in MachO: '{}'",
            filepath.bold()
        );

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(file);

        for s in &bin.segments {
            if s.flags & constants::S_ATTR_PURE_INSTRUCTIONS == 0
                || s.flags & constants::S_ATTR_SOME_INSTRUCTIONS == 0
            {
                continue;
            }

            let section_name = match std::str::from_utf8(&s.segname) {
                Ok(v) => String::from(v).replace("\0", ""),
                Err(_) => "".to_string(),
            };

            let mut section = Section::new(s.vmaddr as u64, (s.vmaddr + s.vmsize - 1) as u64);

            section.name = section_name;

            let perm = Permission::EXECUTABLE | Permission::READABLE; // todo: fix later
            section.permission = perm;

            reader.seek(SeekFrom::Start(s.fileoff as u64)).unwrap();
            reader.read_exact(&mut section.data).unwrap();

            debug!("Adding {}", section);

            sections.push(section);
        }

        let cpu: Box<dyn cpu::Cpu> = match bin.header.cputype {
            constants::cputype::CPU_TYPE_X86 => Box::new(cpu::x86::X86 {}),
            constants::cputype::CPU_TYPE_X86_64 => Box::new(cpu::x86::X64 {}),
            constants::cputype::CPU_TYPE_ARM64 => Box::new(cpu::arm::Arm64 {}),
            constants::cputype::CPU_TYPE_ARM => Box::new(cpu::arm::Arm {}),
            _ => {
                panic!("MachO is corrupted")
            }
        };

        Self {
            path: path.clone(),
            sections: sections,
            cpu: cpu,
            entry_point: bin.entry,
        }
    }
}

impl ExecutableFormat for Mach {
    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn format(&self) -> Format {
        Format::Mach
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
