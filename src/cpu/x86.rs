use std::vec;

use crate::cpu;

pub struct X86;

impl cpu::Cpu for X86 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::X86
    }

    fn ptrsize(&self) -> usize {
        4
    }

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (vec![0xc3], vec![0xff]),                         // ret
            (vec![0xcb], vec![0xff]),                         // retf
            (vec![0xc2, 0x00, 0x00], vec![0xff, 0x00, 0x00]), // ret imm16
            (vec![0xcf, 0x00, 0x00], vec![0xff, 0x00, 0x00]), // retf imm16
        ]
    }

    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![0xe8, 0x00, 0x00, 0x00, 0x00],
                vec![0xff, 0x00, 0x00, 0x00, 0x00],
            ), // CALL rel32
            (vec![0xff, 0xd0], vec![0xff, 0xf0]), // CALL REG32
            (vec![0xff, 0b0001_0000], vec![0xff, 0b1111_0000]), // CALL [REG32]
            (vec![0xff, 0b0101_0001, 0], vec![0xff, 0b1111_0000, 0]), // CALL [REG32+DISP8]
        ]
    }

    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (vec![0xe9, 0, 0, 0, 0], vec![0xff, 0, 0, 0, 0]), // JMP imm32
            (vec![0xFF, 0xe7], vec![0xff, 0xf8]),             // JMP REG32
        ]
    }

    fn insn_step(&self) -> usize {
        1
    }
}

impl std::fmt::Debug for X86 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X86").finish()
    }
}

pub struct X64;

impl cpu::Cpu for X64 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::X64
    }

    fn ptrsize(&self) -> usize {
        8
    }

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (vec![0xc3], vec![0xff]),                         // RET
            (vec![0xcb], vec![0xff]),                         // RETF
            (vec![0xc2, 0x00, 0x00], vec![0xff, 0x00, 0x00]), // RET imm16
            (vec![0xcf, 0x00, 0x00], vec![0xff, 0x00, 0x00]), // RETF imm16
        ]
    }

    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![0xe8, 0x00, 0x00, 0x00, 0x00],
                vec![0xff, 0x00, 0x00, 0x00, 0x00],
            ), // CALL rel32
            (vec![0xff, 0xd0], vec![0xff, 0xf0]), // CALL REG64
            (vec![0x41, 0xff, 0xd0], vec![0xff, 0xff, 0xf0]), // CALL REX.W REG64
            (vec![0xff, 0b0001_0000], vec![0xff, 0b1111_0000]), // CALL [REG64]
            (vec![0x41, 0xff, 0b0001_0000], vec![0x41, 0xff, 0b1111_0000]), // CALL [REX.W REG64]
            (vec![0xff, 0b0101_0001, 0], vec![0xff, 0b1111_0000, 0]), // CALL [REG64+DISP8]
            (
                vec![0x41, 0xff, 0b0101_0001, 0],
                vec![0xff, 0xff, 0b1111_0000, 0],
            ), // CALL [REX.W REG64+DISP8]
        ]
    }

    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (vec![0xff, 0xe0], vec![0xff, 0xf8]),             // JMP REG64
            (vec![0x41, 0xff, 0xe0], vec![0xff, 0xff, 0xf8]), // JMP REX.W REG64
            (vec![0xeb, 0x00], vec![0xff, 0x00]),             // JMP imm8
            (vec![0xe9, 0, 0, 0, 0], vec![0xff, 0, 0, 0, 0]), // JMP imm32
        ]
    }

    fn insn_step(&self) -> usize {
        1
    }
}

impl std::fmt::Debug for X64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X64").finish()
    }
}
