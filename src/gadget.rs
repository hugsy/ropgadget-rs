extern crate capstone;

use std::cmp::Ordering;
use std::{fmt, thread};
use std::{
    io::{Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

use colored::*;
use log::{debug, warn};

use crate::common::GenericResult;
use crate::cpu;
use crate::engine::Disassembler;
use crate::section::Section;
use crate::session::{RopProfileStrategy, Session};

use clap::ValueEnum;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum InstructionGroup {
    Undefined,
    Jump,
    Call,
    Ret,
    Int,
    Iret,
    Privileged,
}

impl std::fmt::Display for InstructionGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Instruction {
    pub size: usize,
    pub raw: Vec<u8>,
    pub address: u64,
    pub group: InstructionGroup,

    pub mnemonic: String,
    pub operands: Option<String>,
}

impl Instruction {
    pub fn text(&self, use_color: bool) -> String {
        let mnemo = match use_color {
            true => {
                format!("{}", self.mnemonic.cyan())
            }
            false => self.mnemonic.to_string(),
        };

        let op = match &self.operands {
            Some(x) => {
                if use_color {
                    format!(" {}", x.bold())
                } else {
                    format!(" {}", x)
                }
            }
            None => "".to_string(),
        };

        format!("{}{}", mnemo, op)
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Instruction(addr=0x{:x}, size={}, text='{}', raw={:?}, group={:?})",
            self.address,
            self.size,
            self.text(false),
            self.raw,
            self.group
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Gadget {
    pub address: u64,
    pub insns: Vec<Instruction>,
    pub size: usize,  // sum() of sizeof(each_instruction)
    pub raw: Vec<u8>, // concat() of instruction.raw
}

impl fmt::Display for Gadget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Gadget(addr={:#x}, text='{}')",
            self.address,
            self.text(false)
        )
    }
}

impl Gadget {
    pub fn new(insns: Vec<Instruction>) -> Self {
        //
        // by nature, we should never be here if insns.len() is 0 (should at least have the
        // ret insn) so we assert() to be notified
        //
        if insns.is_empty() {
            std::panic::panic_any("GadgetBuildError");
        }

        let size = insns.iter().map(|x| x.size).sum();

        let raw = insns.iter().flat_map(|x| x.raw.clone()).collect();

        let address = insns.first().unwrap().address;

        Self {
            size,
            raw,
            address,
            insns,
        }
    }

    pub fn text(&self, use_color: bool) -> String {
        self.insns
            .iter()
            .map(|i| i.text(use_color).clone() + " ; ")
            .collect()
    }
}

fn collect_previous_instructions(
    session: &Arc<Session>,
    group: &Vec<(Vec<u8>, Vec<u8>)>,
    memory_chunk: &Vec<u8>,
) -> GenericResult<Vec<(usize, usize)>> {
    let mut res: Vec<(usize, usize)> = Vec::new();

    for (opcodes, mask) in group {
        let sz = opcodes.len();

        let mut v: Vec<(usize, usize)> = memory_chunk
            .windows(sz)
            .enumerate()
            .filter(|(_, y)| {
                y.iter()
                    .enumerate()
                    .map(|(i, z)| z & mask[i])
                    .cmp(opcodes.to_owned())
                    == Ordering::Equal
            })
            .map(|(x, _)| (x, sz))
            .collect();

        res.append(&mut v);

        match session.profile_type {
            RopProfileStrategy::Fast => {
                break;
            }
            _ => {}
        }
    }

    Ok(res)
}

pub fn get_all_valid_positions_and_length(
    session: &Arc<Session>,
    cpu: &Box<dyn cpu::Cpu>,
    section: &Section,
    cursor: usize,
) -> GenericResult<Vec<(usize, usize)>> {
    let data = &section.data[cursor..].to_vec();

    let mut groups = Vec::new();

    for gadget_type in &session.gadget_types {
        match gadget_type {
            InstructionGroup::Ret => {
                debug!("inserting ret positions and length...");
                groups.append(&mut cpu.ret_insns().clone());
            }
            InstructionGroup::Call => {
                debug!("inserting call positions and length...");
                groups.append(&mut cpu.call_insns().clone());
            }
            InstructionGroup::Jump => {
                debug!("inserting jump positions and length...");
                groups.append(&mut cpu.jmp_insns().clone());
            }
            InstructionGroup::Int => todo!(),
            InstructionGroup::Iret => todo!(),
            InstructionGroup::Privileged => todo!(),
            InstructionGroup::Undefined => todo!(),
        }
    }

    collect_previous_instructions(session, &groups, data)
}

///
/// from the section.data[pos], disassemble previous instructions
///
pub fn find_gadgets_from_position(
    session: Arc<Session>,
    engine: &dyn Disassembler,
    section: &Section,
    initial_position: usize,
    initial_len: usize,
    cpu: &Box<dyn cpu::Cpu>,
) -> GenericResult<Vec<Gadget>> {
    let max_invalid_size = match cpu.cpu_type() // todo: use session.max_gadget_length
    {
        cpu::CpuType::X86 => { 16 }
        cpu::CpuType::X64 => { 16 }
        cpu::CpuType::ARM64 => { 16 }
        cpu::CpuType::ARM => { 16 }
        cpu::CpuType::Unknown => panic!(),
    };

    let start_address = section.start_address;
    let s: usize = if initial_position < max_invalid_size {
        0
    } else {
        initial_position - max_invalid_size
    };
    let data = &section.data[s..initial_position + initial_len];
    let mut cur = Cursor::new(data);

    //
    // browse the section for the largest gadget
    //

    let mut sz: usize = initial_len;
    let mut nb_invalid = 0;
    let step = cpu.insn_step();
    let mut gadgets: Vec<Gadget> = Vec::new();

    loop {
        let mut candidate: Vec<u8> = vec![0; sz];

        //
        // ensure we're still within the boundaries of the cursor
        //
        if (sz - step) >= data.len() {
            break;
        }

        //
        // jump to the position in the file
        //
        let current_position = -((sz - step) as i64);

        cur.seek(SeekFrom::End(current_position - step as i64))?;
        if cur.read_exact(&mut candidate).is_err() {
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
        match insns {
            Some(x) => {
                nb_invalid = 0;
                if !x.is_empty() {
                    let last_insn = x.last().unwrap();
                    if session.gadget_types.contains(&last_insn.group) {
                        let gadget = Gadget::new(x);
                        if gadgets.iter().all(|x| x.address != gadget.address) {
                            debug!(
                                "{:?}: pushing new gadget(address={:x}, sz={})",
                                thread::current().id(),
                                gadget.address,
                                gadget.raw.len()
                            );
                            gadgets.push(gadget);
                        }
                    }
                }
            }

            None => {
                nb_invalid += 1;
                if nb_invalid == max_invalid_size {
                    break;
                }
            }
        }

        sz += step;
    }

    Ok(gadgets)
}
