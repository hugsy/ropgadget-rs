extern crate capstone;

// use std::borrow::Borrow;
use std::{default, fmt, thread};
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

#[derive(std::fmt::Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum InstructionGroup {
    Undefined,
    #[default]
    Ret,
    Jump,
    Call,
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

//
// Search for a given group of opcodes in the memory chunks.
// It effectively split the memory chunk into a vector a [position; length]
// matching the opcode pattern (i.e. bytes & mask)
//
fn collect_previous_instructions(
    session: &Arc<Session>,
    group: &Vec<(Vec<u8>, Vec<u8>)>,
    memory_chunk: &Vec<u8>,
) -> GenericResult<Vec<(usize, usize)>> {
    let mut out = Vec::<(usize, usize)>::new();

    for (bytes, mask) in group {
        //
        // For each possible opcode:
        // - inspect the memory memory chunk
        // - split into chunks of a length of the opcode, and enumerate
        // them to add an index
        // - map each byte of the "sub-chunk" and AND-it with the mask from the
        // pattern group, and finally compare the result to the bytes from the
        // pattern
        // - filter the matches, and collect them into a result vector
        //
        let bytes_length = bytes.len();
        let chunks: Vec<(usize, usize)> = memory_chunk
            .windows(bytes_length)
            .enumerate()
            .filter(|(_, chunk)| {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| byte & mask[i])
                    .cmp(bytes.to_owned())
                    .is_eq()
            })
            .map(|(pos, _)| (pos, bytes_length))
            .collect();

        if chunks.len() > 0 {
            out.extend(chunks);

            match session.profile_type {
                RopProfileStrategy::Fast => {
                    break;
                }
                RopProfileStrategy::Complete => {}
            }
        }
    }

    Ok(out)
}

pub fn get_all_valid_positions_and_length(
    session: &Arc<Session>,
    cpu: &Box<dyn cpu::Cpu>,
    section: &Section,
    cursor: usize,
) -> GenericResult<Vec<(usize, usize)>> {
    let data = &section.data[cursor..].to_vec();

    let groups = match &session.gadget_type {
        InstructionGroup::Ret => {
            debug!("inserting ret positions and length...");
            cpu.ret_insns()
        }
        InstructionGroup::Call => {
            debug!("inserting call positions and length...");
            cpu.call_insns()
        }
        InstructionGroup::Jump => {
            debug!("inserting jump positions and length...");
            cpu.jmp_insns()
        }
        InstructionGroup::Int => todo!(),
        InstructionGroup::Iret => todo!(),
        InstructionGroup::Privileged => todo!(),
        InstructionGroup::Undefined => panic!(),
    };

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
    let max_invalid_size = cpu.max_rewind_size();

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
                    if &session.gadget_type == &last_insn.group {
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
