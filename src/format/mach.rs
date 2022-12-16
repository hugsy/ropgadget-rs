use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use colored::Colorize;
use goblin::mach::{constants, Mach, MachO};
use log::debug;

use crate::{
    common::GenericResult, cpu::arm::ARM, cpu::arm::ARM64, cpu::x64::X64, cpu::x86::X86,
    error::Error, format::Format, section::Permission, section::Section, session::Session,
};

///
///
///
pub fn prepare_mach_file(session: &mut Session, mach: &Mach) -> GenericResult<Vec<Section>> {
    if session.info.format.is_none() {
        session.info.format = Some(Format::Mach);
    } else {
        if let Some(fmt) = &session.info.format {
            match fmt {
                Format::Mach => {}
                _ => {
                    return Err(Error::MismatchFileFormatError(
                        "incorrect format specified as parameter",
                    ));
                }
            }
        }
    }

    match mach {
        Mach::Fat(_) => {
            todo!()
        }
        Mach::Binary(macho) => prepare_macho_file(session, macho),
    }
}

///
///
///
fn prepare_macho_file(session: &mut Session, macho: &MachO) -> GenericResult<Vec<Section>> {
    session.info.entry_point_address = macho.entry as u64;

    if session.info.cpu.is_none() {
        session.info.cpu = match macho.header.cputype {
            constants::cputype::CPU_TYPE_X86 => Some(Box::new(X86 {})),
            constants::cputype::CPU_TYPE_X86_64 => Some(Box::new(X64 {})),
            constants::cputype::CPU_TYPE_ARM64 => Some(Box::new(ARM64 {})),
            constants::cputype::CPU_TYPE_ARM => Some(Box::new(ARM {})),
            _ => {
                panic!("MachO is corrupted")
            }
        };
    }

    collect_executable_sections(&session.filepath, macho)
}

///
///
///
fn collect_executable_sections(path: &PathBuf, macho: &MachO) -> GenericResult<Vec<Section>> {
    let filepath = path.to_str().unwrap();

    let mut sections: Vec<Section> = Vec::new();

    debug!(
        "looking for executables sections in MachO: '{}'",
        filepath.bold()
    );

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    for s in &macho.segments {
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

        reader.seek(SeekFrom::Start(s.fileoff as u64))?;
        reader.read_exact(&mut section.data)?;

        debug!("adding MachO {}", section);

        sections.push(section);
    }

    Ok(sections)
}
