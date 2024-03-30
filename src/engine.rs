use capstone::prelude::*;

use crate::cpu::{Cpu, CpuType};
use crate::gadget::{Instruction, InstructionGroup};

/**
 *
 * for now we just use capstone, but can be easily updated to other engines
 * in this case, change engine.rs -> engine/mod.rs and put the engines there
 *
 */

pub enum DisassemblyEngineType {
    Invalid,
    Capstone,
}

impl Default for DisassemblyEngineType {
    fn default() -> Self {
        DisassemblyEngineType::Invalid
    }
}

//
// All disassembler must implement this trait
//
pub trait Disassembler {
    fn disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>>;
    fn name(&self) -> String;
    fn id(&self) -> DisassemblyEngineType;
}

pub struct DisassemblyEngine {
    pub disassembler: Box<dyn Disassembler>,
}

impl DisassemblyEngine {
    ///
    ///
    ///
    pub fn new(engine_type: &DisassemblyEngineType, cpu: &dyn Cpu) -> Self {
        match engine_type {
            DisassemblyEngineType::Capstone => Self {
                disassembler: Box::new(CapstoneDisassembler::new(cpu)),
            },
            DisassemblyEngineType::Invalid => panic!(),
        }
    }
}

impl std::fmt::Display for DisassemblyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Engine({})", self.disassembler.name())
    }
}

///
/// Capstone disassembler implementation
///

// https://github.com/aquynh/capstone/blob/1b5014515d0d671048e2b43ce483d38d85a2bc83/bindings/python/capstone/__init__.py#L216
const INSN_GRP_JUMP: u8 = 0x01;
const INSN_GRP_CALL: u8 = 0x02;
const INSN_GRP_RET: u8 = 0x03;
const INSN_GRP_INT: u8 = 0x04;
const INSN_GRP_IRET: u8 = 0x05;
const INSN_GRP_PRIV: u8 = 0x06;

pub struct CapstoneDisassembler {
    cs: Capstone,
}

impl Disassembler for CapstoneDisassembler {
    fn disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>> {
        self.cs_disassemble(code, address)
    }

    fn name(&self) -> String {
        // todo: add version strings
        let (major, minor) = Capstone::lib_version();
        format!("Capstone-Engine({}.{})", major, minor)
    }

    fn id(&self) -> DisassemblyEngineType {
        DisassemblyEngineType::Capstone
    }
}

impl std::fmt::Display for CapstoneDisassembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Disassembler({})", self.name())
    }
}

impl CapstoneDisassembler {
    fn new(cpu: &dyn Cpu) -> Self {
        let cs = match cpu.cpu_type() {
            CpuType::X86 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),

            CpuType::X64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),

            CpuType::ARM => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),

            CpuType::ARM64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),

            CpuType::Unknown => panic!(),
        };

        Self { cs }
    }

    fn cs_disassemble(&self, code: &Vec<u8>, address: u64) -> Option<Vec<Instruction>> {
        let cs_insns = self
            .cs
            .disasm_all(&code, address)
            .expect("Failed to disassemble");

        //
        // Any instruction?
        //
        if cs_insns.len() == 0 {
            return None;
        }

        //
        // Otherwise we're good to proceed
        //
        let mut insns: Vec<Instruction> = Vec::new();
        let mut candidates: Vec<Instruction> = Vec::new();

        for cs_insn in cs_insns.iter() {
            let detail: InsnDetail = self.cs.insn_detail(&cs_insn).unwrap();

            let mut insn_group = InstructionGroup::Undefined;

            for cs_insn_group in detail.groups() {
                insn_group = match cs_insn_group.0 {
                    INSN_GRP_JUMP => InstructionGroup::Jump,
                    INSN_GRP_CALL => InstructionGroup::Call,
                    INSN_GRP_RET => InstructionGroup::Ret,
                    INSN_GRP_PRIV => InstructionGroup::Privileged,
                    INSN_GRP_INT => InstructionGroup::Int,
                    INSN_GRP_IRET => InstructionGroup::Iret,
                    _ => {
                        continue;
                    }
                };
            }

            let mnemonic = cs_insn.mnemonic().unwrap().to_string();

            let operands: Option<String> = match cs_insn.op_str() {
                // todo: do better parsing on args
                Some(op) => Some(op.to_string()),
                None => None,
            };

            let insn = Instruction {
                raw: cs_insn.bytes().to_vec(),
                size: cs_insn.bytes().len(),
                mnemonic,
                operands,
                address: cs_insn.address(),
                group: insn_group,
            };

            candidates.push(insn);
        }

        //
        // at this point `candidates` holds a valid set of Instruction
        // must filter out the sequence that can't qualify for a rop sequence
        //
        for insn in candidates.into_iter().rev() {
            match insn.group {
                InstructionGroup::Jump => {
                    if insns.len() > 0 {
                        break;
                    }
                }
                InstructionGroup::Call => {
                    if insns.len() > 0 {
                        break;
                    }
                }
                InstructionGroup::Ret => {
                    if insns.len() > 0 {
                        break;
                    }
                }
                _ => {}
            };

            insns.insert(0, insn);
        }

        Some(insns)
    }
}
