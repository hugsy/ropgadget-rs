use colored::Colorize;
use goblin;
use log::{debug, trace};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::cpu;
use crate::{format::Format, section::Section};

use super::ExecutableFormat;

#[derive(Debug)]
pub struct Elf {
    path: PathBuf,
    sections: Vec<Section>,
    cpu: Box<dyn cpu::Cpu>,
    entry_point: u64,
}

impl Elf {
    pub fn new(path: PathBuf, obj: goblin::elf::Elf) -> Self {
        let filepath = path.to_str().unwrap();

        let mut executable_sections: Vec<Section> = Vec::new();
        debug!("looking for executables s in ELF: '{}'", filepath.bold());

        let file = File::open(&path).unwrap();
        let mut reader = BufReader::new(file);

        for s in &obj.section_headers {
            trace!("Testing section {:?}", s);

            //
            // disregard non executable section
            //
            if !s.is_executable() {
                continue;
            }

            debug!("Importing section {:?}", s);

            let mut section = Section::from(s);
            section.name = String::from(&obj.shdr_strtab[s.sh_name]);

            if reader.seek(SeekFrom::Start(s.sh_addr as u64)).is_err() {
                panic!(
                    "Invalid offset {} for section '{}', corrupted ELF?",
                    s.sh_addr, section.name
                )
            }

            match reader.read_exact(&mut section.data) {
                Ok(_) => {
                    executable_sections.push(section);
                }
                Err(e) => panic!("Failed to read '{}' section: {:?}", section.name, e),
            };
        }

        let cpu: Box<dyn cpu::Cpu> = match obj.header.e_machine {
            goblin::elf::header::EM_386 => Box::new(cpu::x86::X86 {}),
            goblin::elf::header::EM_X86_64 => Box::new(cpu::x86::X64 {}),
            goblin::elf::header::EM_ARM => Box::new(cpu::arm::Arm {}),
            goblin::elf::header::EM_AARCH64 => Box::new(cpu::arm::Arm {}),
            _ => {
                panic!("ELF machine format is unsupported")
            }
        };

        Self {
            path: path.clone(),
            sections: executable_sections,
            cpu: cpu,
            entry_point: obj.entry,
        }
    }
}

impl ExecutableFormat for Elf {
    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn format(&self) -> Format {
        Format::Elf
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
