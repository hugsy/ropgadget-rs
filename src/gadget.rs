extern crate capstone;

use std::fmt;
use std::io::{Cursor, Read};
use std::sync::Arc;

use log::{debug, trace};
use capstone::prelude::*;

use crate::error::Error;
use crate::{section::Section, };
use crate::{common::GenericResult, };
use crate::cpu;


// https://github.com/aquynh/capstone/blob/1b5014515d0d671048e2b43ce483d38d85a2bc83/bindings/python/capstone/__init__.py#L216
const INSN_GRP_JUMP: u8 = 0x01;
const INSN_GRP_CALL: u8 = 0x02;
const INSN_GRP_RET:  u8 = 0x03;
const INSN_GRP_INT:  u8 = 0x04;
const INSN_GRP_IRET: u8 = 0x05;
const INSN_GRP_PRIV: u8 = 0x06;


#[derive(Debug)]
pub struct Instruction
{
    size: usize,
    raw: Vec<u8>,
    text: String,
    addr: u64,
}

impl fmt::Display for Instruction
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Instruction(addr={:x}, size={}, text='{}', raw={:?})", self.addr, self.size, self.text, self.raw)
    }
}


#[derive(Debug)]
pub struct Gadget
{
    pub addr: u64,
    pub insns: Vec<Instruction>,
    pub size: usize,    // sum() of sizeof(each_instruction)
    pub raw: Vec<u8>,   // concat() of instruction.raw
    pub text: String,   // concat() instruction.text
}


impl fmt::Display for Gadget
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "Gadget(addr={:#x}, text='{}')", self.addr, self.text)
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

        debug!("building new gadget...");

        Self {
            size: insns
                .iter()
                .map(|x| x.size)
                .sum(),
            text: insns
                .iter()
                .map(|x| x.text.clone() + " ; ")
                .collect(),
            raw: insns
                .iter()
                .map(|x| x.raw.clone())
                .flatten()
                .collect(),
            addr: insns.get(0).unwrap().addr,
            insns: insns,
        }
    }
}


pub fn get_all_return_positions(cpu: Arc<dyn cpu::Cpu>, section: &Section) -> GenericResult<Vec<usize>>
{
    let data = &section.data;
    let res: Vec<usize> = data
        .iter()
        .enumerate()
        .filter(|x| (x.1) == cpu.ret_insn().get(0).unwrap())
        .map(|x| x.0 )
        .collect();

    Ok(res)
}


///
/// from the c3 at section.data[pos], disassemble previous insn
///
pub fn find_biggest_gadget_from_position(engine: &DisassemblyEngine, section: &Section, pos: usize) -> GenericResult<Gadget>
{
    let mut cur = Cursor::new(&section.data);

    //
    // browse the section for the largest gadget
    //

    let mut sz: usize = 1;
    let mut last_valid_insns: Vec<Instruction> = Vec::new();


    loop
    {
        let mut candidate: Vec<u8> = vec![0; sz];

        //
        // prevent underflow
        //
        if sz+1 > pos
        {
            break;
        }

        let new_pos = (pos-sz+1) as u64;

        cur.set_position(new_pos as u64);
        if cur.read_exact(&mut candidate).is_err()
        {
            break;
        }

        let addr = section.start_address + cur.position();
        let insns = engine.disassembler.disassemble(&candidate, addr);
        match insns
        {
            Some(x) =>
            {
                if x.len() > 0
                {
                    let last_insn = x.last().unwrap().raw.get(0).unwrap();
                    if *last_insn == 0xc3
                    {
                        last_valid_insns = x;
                    }
                }
            },
            None => {
                let gadget = Gadget::new(last_valid_insns);
                debug!("largest sequence from {:x} is {}B long", pos, gadget.raw.len());
                return Ok(gadget);
            }
        }

        sz += 1;
    }

    Err( Error::GadgetBuildError() )
}







pub enum DisassemblyEngineType
{
    Capstone,
}


pub trait Disassembler
{
    fn disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>>;
}


pub struct DisassemblyEngine
{
    pub engine_type: DisassemblyEngineType,
    pub name: String,
    pub disassembler: Box<dyn Disassembler>,
}


impl DisassemblyEngine
{
    pub fn new(engine_type: DisassemblyEngineType ) -> Self
    {
        match engine_type
        {
            DisassemblyEngineType::Capstone =>
            {
                Self
                {
                    engine_type: DisassemblyEngineType::Capstone,
                    disassembler: Box::new(CapstoneDisassembler{}),
                    name: "Capstone-Engine".to_string(),
                }
            }
        }
    }
}


pub struct CapstoneDisassembler {}


impl Disassembler for CapstoneDisassembler
{
    fn disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>>
    {
        //
        // placeholders for future disassemblers, for now just capstone
        //
        self.cs_disassemble(code, address)
    }
}


impl CapstoneDisassembler
{
    fn cs_disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>>
    {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");


        let cs_insns = cs.disasm_all(&code, address)
            .expect("Failed to disassemble");

        if cs_insns.len() > 0
        {
            let mut insns : Vec<Instruction> = Vec::new();

            for cs_insn in cs_insns.iter()
            {
                let mut should_skip = false;

                let detail: InsnDetail = cs.insn_detail(&cs_insn).unwrap();
                // https://github.com/capstone-rust/capstone-rs/blob/master/capstone-sys/capstone/suite/test_group_name.py#L172
                trace!("insn '{} {}', detail={}",
                      cs_insn.mnemonic().unwrap_or("").to_string(),
                      cs_insn.op_str().unwrap_or("").to_string(),
                      detail
                          .groups()
                          .map(|x| cs.group_name(x.into()).unwrap())
                          .collect::<Vec<String>>()
                          .join(",")
                );


                for insn_group in detail.groups()
                {
                    match insn_group.0
                    {
                        INSN_GRP_JUMP => { should_skip = true }
                        INSN_GRP_CALL => { should_skip = true }
                        INSN_GRP_PRIV => { should_skip = true }
                        INSN_GRP_INT => { should_skip = true }
                        INSN_GRP_IRET => { should_skip = true }
                        INSN_GRP_RET => { should_skip = insns.len() > 0 }
                        _ => {should_skip = false;}
                    }
                }

                if should_skip
                {
                    break;
                }


                let mut text = cs_insn.mnemonic().unwrap().to_string();

                if let Some(ops) = cs_insn.op_str()
                {
                    if ops.len() > 0
                    {
                        text += " ";
                        text += &ops.to_string();
                    }
                }


                insns.push(
                    Instruction
                    {
                        raw: cs_insn.bytes().to_vec(),
                        size: cs_insn.bytes().len(),
                        text: text,
                        addr: cs_insn.address(),
                    }
                );
            }

            return Some(insns);
        }

        None
    }
}