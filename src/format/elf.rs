use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufReader};
use goblin::elf::Elf;
use log::{debug, trace};
use colored::*;

use crate::{
    error::Error,
    section::Permission,
    section::Section,
    common::GenericResult,
    session::Session,

    cpu::x86::X86,
    cpu::x64::X64,

    format::Format,
};


pub fn prepare_elf_file(session: &mut Session, elf: &Elf ) -> GenericResult<Vec<Section>>
{
    session.info.entry_point_address = elf.entry as u64;

    if session.info.format.is_none()
    {
        session.info.format = Some(Format::Elf);
    }
    else
    {
        if let Some(fmt) = &session.info.format
        {
            match fmt
            {
                Format::Elf => {}
                _ => { return Err(Error::MismatchFileFormatError("incorrect format specified as parameter")); }
            }
        }
    }


    if session.info.cpu.is_none()
    {
        session.info.cpu = match elf.header.e_machine
        {
            goblin::elf::header::EM_386 => { Some(Box::new(X86{})) }
            goblin::elf::header::EM_X86_64 => { Some(Box::new(X64{})) }
            /*
            goblin::elf::header::EM_ARM =>
            {
                if elf.is_64
                {
                    Box::new(cpu::arm64::ARM64{})
                }
                else
                {
                    Box::new(cpu::arm64::ARM{})
                }
            }
            */
            goblin::elf::header::EM_ARM => { todo!() }
            _ => { panic!("Elf is corrupted") }
        };
    }


    collect_executable_sections(&session.filepath, elf)
}


fn collect_executable_sections(path: &str, elf: &Elf) -> GenericResult<Vec<Section>>
{
    let mut executable_sections : Vec<Section> = Vec::new() ;
    debug!("looking for executables s in ELF: '{}'", path.bold());


    let file = File::open(path)?;
    let mut reader = BufReader::new( file);

    for s in &elf.section_headers
    {
        trace!("{:?}", s);

        //
        // disregard non executable section
        //
        if !s.is_executable()
        {
            continue;
        }

        let mut perm = Permission::READABLE | Permission::EXECUTABLE;

        if s.is_writable()
        {
            perm |= Permission::WRITABLE;
        }

        let section_name = &elf.shdr_strtab[s.sh_name];

        let mut section = Section::new(
            s.sh_addr as u64,
            (s.sh_addr + s.sh_size - 1) as u64
        );

        section.permission = perm;
        section.name = section_name.to_string();

        reader.seek(SeekFrom::Start(s.sh_addr as u64))?;
        reader.read_exact( &mut section.data )?;

        executable_sections.push(section);
    }


    Ok(executable_sections)
}

