use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufReader};

use goblin::pe::PE;
use colored::*;
use log::{debug,};

use crate::{
    section::Permission,
    section::Section,
    common::GenericResult,
    error::Error,
    session::Session,

    cpu::x86::X86,
    cpu::x64::X64,

    format::Format,
};


///
///
///
pub fn prepare_pe_file(session: &mut Session, pe: &PE ) -> GenericResult<Vec<Section>>
{
    session.info.entry_point_address = pe.entry as u64;


    if session.info.format.is_none()
    {
        session.info.format = Some(Format::Pe);
    }
    else
    {
        if let Some(fmt) = &session.info.format
        {
            match fmt
            {
                Format::Pe => {}
                _ => { return Err(Error::MismatchFileFormatError("incorrect format specified as parameter")); }
            }
        }
    }



    if session.info.cpu.is_none()
    {
        //
        // if cpu is none, no arg was given on the command line
        // try to determine the arch from the binary itself
        //
        session.info.cpu = match pe.header.coff_header.machine
        {
            goblin::pe::header::COFF_MACHINE_X86 => { Some(Box::new(X86{})) }
            goblin::pe::header::COFF_MACHINE_X86_64 => { Some(Box::new(X64{})) }
            goblin::pe::header::COFF_MACHINE_ARM => { todo!() /*Box::new(cpu::arm64::ARM64{})*/ }
            goblin::pe::header::COFF_MACHINE_ARM64 => { todo!() /*Box::new(cpu::arm::ARM{})*/ }
            _ => { panic!("PE is corrupted") }
        };
    }


    collect_executable_sections(&session.filepath, pe)
}



///
///
///
fn collect_executable_sections(path: &str, pe: &PE) -> GenericResult<Vec<Section>>
{
    let mut executable_sections : Vec<Section> = Vec::new() ;

    debug!("looking for executable sections in PE: '{}'", path.bold());

    let file = File::open(path)?;
    let mut reader = BufReader::new( file);

    for s  in &pe.sections
    {
        if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE == 0
        {
            continue;
        }

        let section_name = match std::str::from_utf8(&s.name)
        {
            Ok(v)  => String::from(v).replace("\0", ""),
            Err(_) => String::new()
        };

        let mut section = Section::new(
            s.virtual_address as u64,
            (s.virtual_address + s.virtual_size - 1) as u64
        );

        section.name = section_name;

        let mut perm = Permission::EXECUTABLE;
        if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0
        {
            perm |= Permission::READABLE;
        }

        if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0
        {
            perm |= Permission::WRITABLE;
        }

        section.permission = perm;

        reader.seek(SeekFrom::Start( s.pointer_to_raw_data as u64))?;
        reader.read_exact( &mut section.data )?;

        debug!("adding {}", section);
        executable_sections.push(section);
    }

    Ok(executable_sections)
}

