extern crate capstone;

use std::fmt;
use std::io::{Cursor, Read, SeekFrom, Seek};

use log::{debug, warn};
use colored::*;

use crate::{section::Section, };
use crate::{common::GenericResult, };
use crate::cpu;
use crate::error;
use crate::engine::{DisassemblyEngine, };



#[derive(Debug, Copy, Clone, PartialEq)]
pub enum InstructionGroup
{
    Undefined,
    Jump,
    Call,
    Ret,
    Int,
    Iret,
    Privileged,
}


#[derive(Debug, PartialEq)]
pub struct Instruction
{
    pub size: usize,
    pub raw: Vec<u8>,
    pub address: u64,
    pub group: InstructionGroup,

    pub mnemonic : String,
    pub operands : Option<String>,
}

impl Instruction
{
    pub fn text(&self, use_color: bool) -> String
    {
        let mnemo = match use_color
        {
            true => {format!("{}", self.mnemonic.cyan())}
            false => {format!("{}", self.mnemonic)}
        };

        let op = match &self.operands
        {
            Some(x) =>
            {
                if use_color { format!(" {}", x.bold()) }
                else { format!(" {}", x) }
            }
            None => { "".to_string() }
        };

        format!("{}{}", mnemo, op)
    }
}


impl fmt::Display for Instruction
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Instruction(addr=0x{:x}, size={}, text='{}', raw={:?}, group={:?})", self.address, self.size, self.text(false), self.raw, self.group)
    }
}


#[derive(Debug, PartialEq)]
pub struct Gadget
{
    pub address: u64,
    pub insns: Vec<Instruction>,
    pub size: usize,    // sum() of sizeof(each_instruction)
    pub raw: Vec<u8>,   // concat() of instruction.raw
}


impl fmt::Display for Gadget
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Gadget(addr={:#x}, text='{}')", self.address, self.text(false))
    }
}


impl Gadget
{
    pub fn new(insns: Vec<Instruction>) -> Self
    {
        //
        // by nature, we should never be here if insns.len() is 0 (should at least have the
        // ret insn) so we assert() to be notified
        //
        if insns.len() == 0
        {
            panic!( error::Error::GadgetBuildError );
        }

        let size = insns
            .iter()
            .map(|x| x.size)
            .sum();

        let raw = insns
            .iter()
            .map(|x| x.raw.clone())
            .flatten()
            .collect();

        let address = insns.get(0).unwrap().address;

        Self { size, raw, address, insns }
    }



    pub fn text(&self, use_color: bool) -> String
    {
        self.insns
            .iter()
            .map(|i| i.text(use_color).clone() + " ; ")
            .collect()
    }
}



pub fn get_all_return_positions(cpu: &Box<dyn cpu::Cpu>, section: &Section) -> GenericResult<Vec<usize>>
{
    let data = &section.data;
    let res: Vec<usize> = data
        .iter()
        .enumerate()
        .filter(|x| (x.1) == cpu.ret_insn().get(0).unwrap().get(0).unwrap()) // todo: filter by any of the vec[u8]
        .map(|x| x.0 )
        .collect();

    Ok(res)
}


///
/// from the c3 at section.data[pos], disassemble previous insn
///
pub fn find_gadgets_from_position(engine: &DisassemblyEngine, section: &Section, initial_position: usize, cpu: &Box<dyn cpu::Cpu>) -> GenericResult<Vec<Gadget>>
{
    let max_invalid_size = match cpu.cpu_type() // todo: use session.max_gadget_length
    {
        cpu::CpuType::X86 => { 16 }
        cpu::CpuType::X64 => { 16 }
    };

    let start_address = section.start_address.clone();
    let s: usize = if initial_position < max_invalid_size { 0 } else { initial_position-max_invalid_size };
    let data = &section.data[s..initial_position+1];
    let mut cur = Cursor::new(data);

    //
    // browse the section for the largest gadget
    //

    let mut sz: usize = 1;
    let mut nb_invalid = 0;
    let step = cpu.insn_step();
    let mut gadgets : Vec<Gadget> = Vec::new();

    loop
    {
        let mut candidate: Vec<u8> = vec![0; sz];

        //
        // ensure we're still within the boundaries of the cursor
        //
        if (sz - step) >= data.len()
        {
            break;
        }

        //
        // jump to the position in the file
        //
        let current_position = -((sz-step) as i64);
        cur.seek( SeekFrom::End(current_position-1) )?;
        if cur.read_exact(&mut candidate).is_err()
        {
            warn!("{:?} Cursor reached EOF", std::thread::current().id());
            break;
        }


        //
        // disassemble the code from given position
        //
        let addr = start_address + s as u64 + cur.position() - sz as u64;
        let insns = engine.disassemble(&candidate, addr as u64);

        //
        // transform the Vec<Instruction> into a valid gadget
        //
        match insns
        {
            Some(x) =>
            {
                nb_invalid = 0;
                if x.len() > 0
                {
                    let last_insn = x.last().unwrap();
                    match last_insn.group
                    {
                        InstructionGroup::Ret =>
                        {
                            let gadget = Gadget::new(x);
                            if gadgets.iter().all( |x| x.address != gadget.address )
                            {
                                debug!("pushing new gadget(pos={:x}, sz={}B)", gadget.address, gadget.raw.len());
                                gadgets.push(gadget);
                            }
                        }
                        _ => {}
                    }
                }
            }
            None =>
            {
                nb_invalid += 1;
                if nb_invalid == max_invalid_size
                {
                    //last_valid_insns.clear();
                    break;
                }
            }
        }

        sz += step;
    }

    Ok(gadgets)
}


