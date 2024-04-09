use crate::cpu;

pub struct Arm;

impl cpu::Cpu for Arm {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM
    }

    fn ptrsize(&self) -> usize {
        4
    }

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![(
            vec![0xd6, 0x5f, 0x03, 0xc0].into_iter().rev().collect(),
            vec![0xff, 0xff, 0xff, 0xff].into_iter().rev().collect(),
        )]
    }

    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![0b1101_0001, 0b0010_1111, 0b1111_1111, 0b0001_0000]
                    .into_iter()
                    .rev()
                    .collect(),
                vec![0b1111_1111, 0b1111_1111, 0b1111_1111, 0b1111_0000]
                    .into_iter()
                    .rev()
                    .collect(),
            ), // 4.3 Branch and Exchange (BX)
        ]
    }

    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![]
    }

    fn insn_step(&self) -> usize {
        4
    }

    fn max_rewind_size(&self) -> usize {
        16
    }
}

// impl std::fmt::Debug for Arm {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Arm").finish()
//     }
// }

pub struct Arm64;

impl cpu::Cpu for Arm64 {
    fn cpu_type(&self) -> cpu::CpuType {
        cpu::CpuType::ARM64
    }

    fn ptrsize(&self) -> usize {
        8
    }

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![0xd6, 0x5f, 0x03, 0xc0].into_iter().rev().collect(),
                vec![0xff, 0xff, 0xff, 0xff].into_iter().rev().collect(),
            ), // RET
        ]
    }

    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            // (vec![0x14], vec![0xff]),             // B LABEL
            // (vec![0x01, 0x14], vec![0xff, 0xff]), // BL LABEL
            // (vec![0xd4], vec![0xff]),             // B.cond
            // (vec![0xb4], vec![0xff]),             // CBZ // CBNZ
            (
                vec![0b1101_0110, 0b0011_1111, 0b0000_0000, 0b0000_0000]
                    .into_iter()
                    .rev()
                    .collect(),
                vec![0b1111_1111, 0b1111_1111, 0b1111_0000, 0b0001_1111]
                    .into_iter()
                    .rev()
                    .collect(),
            ), // C6.2.35 BLR
        ]
    }

    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                vec![0b1101_0110, 0b0001_1111, 0b0000_0000, 0b0000_0000]
                    .into_iter()
                    .rev()
                    .collect(),
                vec![0b1111_1111, 0b1111_1111, 0b1111_0000, 0b0001_1111]
                    .into_iter()
                    .rev()
                    .collect(),
            ), // C6.2.37 BR
        ]
    }

    fn insn_step(&self) -> usize {
        4
    }

    fn max_rewind_size(&self) -> usize {
        16
    }
}

// impl std::fmt::Debug for Arm64 {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Arm64").finish()
//     }
// }
