use colored::Colorize;
use goblin;
use log::debug;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::cpu;
use crate::section::Permission;
use crate::{format::FileFormat, section::Section};

use super::ExecutableFileFormat;

pub const ELF_HEADER_MAGIC: &[u8] = b"\x7fELF";

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

    fn sections(&self) -> &Vec<Section> {
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
