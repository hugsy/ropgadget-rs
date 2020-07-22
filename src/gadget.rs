extern crate capstone;

use std::fmt;
use std::io::{Cursor, Read, SeekFrom, Seek};
use std::sync::Arc;

use log::{debug, info, warn};
use colored::*;

use crate::{section::Section, };
use crate::{session::Session, };
use crate::{common::GenericResult, };
use crate::cpu;
use crate::engine::{DisassemblyEngine, };



#[derive(Debug, Copy, Clone)]
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


#[derive(Debug)]
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


#[derive(Debug)]
pub struct Gadget
{
    pub address: u64,
    pub insns: Vec<Instruction>,
    pub size: usize,    // sum() of sizeof(each_instruction)
    pub raw: Vec<u8>,   // concat() of instruction.raw
    pub text: String,   // concat() instruction.text
}


impl fmt::Display for Gadget
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Gadget(addr={:#x}, text='{}')", self.address, self.text)
    }
}


impl Gadget
{
    pub fn new(insns: Vec<Instruction>, use_color : bool) -> Self
    {
        //
        // by nature, we should never be here if insns.len() is 0 (should at least have the
        // ret insn) so we assert() to be notified
        //
        assert!( insns.len() > 0);


        let size = insns
            .iter()
            .map(|x| x.size)
            .sum();

        let text = insns
            .iter()
            .map(|i| i.text(use_color).clone() + " ; ")
            .collect();

        let raw = insns
            .iter()
            .map(|x| x.raw.clone())
            .flatten()
            .collect();

        let address = insns.get(0).unwrap().address;

        Self { size, text, raw, address, insns }
    }
}


pub fn get_all_return_positions(cpu: &Arc<dyn cpu::Cpu>, section: &Section) -> GenericResult<Vec<usize>>
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
pub fn find_gadgets_from_position(engine: &DisassemblyEngine, data: &[u8], start_address: u64, initial_position: usize, cpu: &Arc<dyn cpu::Cpu>, use_color: bool) -> GenericResult<Vec<Gadget>>
{
    let mut cur = Cursor::new(data);

    //
    // browse the section for the largest gadget
    //

    let mut sz: usize = 1;
    let mut nb_invalid = 0;
    let step = cpu.insn_step();
    let mut gadgets : Vec<Gadget> = Vec::new();

    let max_invalid_size = match cpu.cpu_type()
    {
        cpu::CpuType::X86 => { 10 }
        cpu::CpuType::X64 => { 10 }
    };

    loop
    {
        let mut candidate: Vec<u8> = vec![0; sz];

        //
        // prevent underflow
        //
        if (sz - step) >= data.len() //initial_position
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
            warn!("eof");
            break;
        }

        assert_eq!( *candidate.last().unwrap(), 0xc3);

        //
        // disassemble the code from given position
        //
        let addr = start_address + initial_position as u64 + cur.position() - sz as u64;
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
                            let gadget = Gadget::new(x, use_color);
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


