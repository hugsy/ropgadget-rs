use crate::cpu;

pub struct ARM {}

impl cpu::Cpu for ARM {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM
    }

    fn name(&self) -> &str {
        "arm"
    }

    fn ptrsize(&self) -> usize {
        4
        // TODO: thumb
    }

    fn ret_insn(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xc0, 0x03, 0x5f, 0xd6], // RET
        ]
    }

    fn branch_insn(&self) -> Vec<Vec<u8>> {
        vec![]
    }

    fn insn_step(&self) -> usize {
        4
    }
}

pub struct ARM64 {}

impl cpu::Cpu for ARM64 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM64
    }

    fn name(&self) -> &str {
        "arm64"
    }

    fn ptrsize(&self) -> usize {
        8
    }

    fn ret_insn(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xc0, 0x03, 0x5f, 0xd6], // RET
        ]
    }

    fn branch_insn(&self) -> Vec<Vec<u8>> {
        vec![]
    }

    fn insn_step(&self) -> usize {
        4
    }
}
