use crate::cpu;

pub struct X64 {}

impl cpu::Cpu for X64 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::X64
    }

    fn name(&self) -> &str {
        "x86-64"
    }

    fn ptrsize(&self) -> usize {
        8
    }

    fn ret_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xc3],             // ret
            vec![0xcb],             // retf
            vec![0xc2, 0x00, 0x00], // ret imm
            vec![0xca, 0x00, 0x00], // retf imm
        ]
    }

    fn call_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xff, 0x00],
            vec![0xe8, 0x00, 0x00, 0x00, 0x00],
            vec![0xe9, 0x00, 0x00, 0x00, 0x00],
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x00],
        ]
    }

    fn insn_step(&self) -> usize {
        1
    }
}
