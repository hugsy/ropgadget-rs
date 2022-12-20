use crate::cpu;

pub struct Arm;

impl cpu::Cpu for Arm {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM
    }

    fn ptrsize(&self) -> usize {
        4
        // TODO: thumb
    }

    fn ret_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xc0, 0x03, 0x5f, 0xd6], // RET
        ]
    }

    fn call_insns(&self) -> Vec<Vec<u8>> {
        vec![]
    }

    fn jmp_insns(&self) -> Vec<Vec<u8>> {
        vec![]
    }

    fn insn_step(&self) -> usize {
        4
    }
}

impl std::fmt::Debug for Arm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arm").finish()
    }
}

pub struct Arm64;

impl cpu::Cpu for Arm64 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM64
    }

    fn ptrsize(&self) -> usize {
        8
    }

    fn ret_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0xc0, 0x03, 0x5f, 0xd6], // RET
        ]
    }

    fn call_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0x14],      // B LABEL
            vec![0x1, 0x14], // BL LABEL
            vec![0xd4],      // B.cond
            vec![0xb4],      // CBZ // CBNZ
        ]
    }

    fn jmp_insns(&self) -> Vec<Vec<u8>> {
        vec![
            vec![0b1101_0100, 0b0000_1001],                           // J LABEL
            vec![0b1101_0101, 0b0001_0000, 0b0000_0000, 0b0011_1111], // BLR Xn
            vec![0b1101_0101, 0b0001_0000, 0b0000_0000, 0b0011_1111], // ERET
            vec![0b1101_0100, 0b0001_0001, 0b0000_0000, 0b0011_1111], // BR Xn
            vec![0b1101_0101, 0b0000_0000, 0b0000_0000, 0b0011_1111], // RET Xn
        ]
    }

    fn insn_step(&self) -> usize {
        4
    }
}

impl std::fmt::Debug for Arm64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arm64").finish()
    }
}
