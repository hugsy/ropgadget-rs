extern crate capstone;

use std::fmt;
use std::io::{Cursor, Read};
use std::sync::Arc;

use log::{debug, };
use colored::*;

use crate::error::Error;
use crate::{section::Section, };
use crate::{common::GenericResult, };
use crate::cpu;
use crate::engine::{DisassemblyEngine, };



#[derive(Debug, Copy, Clone)]
pub enum InstructionGroup
{
    Invalid,
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
    pub fn text(&self) -> String
    {
        let op = match &self.operands
        {
            Some(x) => { format!(" {}", x.bold()) }
            None => { "".to_string() }
        };

        format!("{}{}", self.mnemonic.cyan(), op)
    }
}


impl fmt::Display for Instruction
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Instruction(addr=0x{:x}, size={}, text='{}', raw={:?}, group={:?})", self.address, self.size, self.text(), self.raw, self.group)
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
    pub fn new(insns: Vec<Instruction>) -> Self
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
            .map(|x| x.text().clone() + " ; ")
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
pub fn find_gadgets_from_position(engine: &DisassemblyEngine, section: &Section, initial_position: usize, cpu: &Arc<dyn cpu::Cpu>) -> GenericResult<Vec<Gadget>>
{
    let mut cur = Cursor::new(&section.data);

    //
    // browse the section for the largest gadget
    //

    let mut sz: usize = 1;
    let step = cpu.insn_step();
    //let mut last_valid_insns: Vec<Instruction> = Vec::new();
    let max_invalid_size = match cpu.cpu_type()
    {
        cpu::CpuType::X86 => { 10 }
        cpu::CpuType::X64 => { 10 }
    };



    let mut nb_invalid = 0;

    let mut gadgets : Vec<Gadget> = Vec::new();

    loop
    {
        let mut candidate: Vec<u8> = vec![0; sz];

        //
        // prevent underflow
        //
        if (sz + step) > initial_position
        {
            break;
        }


        //
        // jump to the position in the file
        //
        let current_position = (initial_position - (sz-step)) as u64;
        cur.set_position(current_position as u64);
        if cur.read_exact(&mut candidate).is_err()
        {
            break;
        }


        let addr = section.start_address + cur.position();
        let insns = engine.disassemble(&candidate, addr - sz as u64);

        //
        // transform the vec<Instruction> into a proper gadget
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
                            debug!("pushing new gadget(pos={:x}, len={}B)", initial_position, gadget.raw.len());
                            gadgets.push(gadget);
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

    /*
    if last_valid_insns.len() > 0
    {
        let gadget = Gadget::new(last_valid_insns);
        debug!("pushing new gadget(pos={:x}, len={}B)", pos, gadget.raw.len());
    }
    */
    return Ok(gadgets);

    //Err( Error::GadgetBuildError() )
}


