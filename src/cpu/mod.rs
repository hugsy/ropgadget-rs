pub mod arm;
pub mod x86;

use clap::ValueEnum;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CpuType {
    X86,
    X64,
    ARM,
    ARM64,
}

pub trait Cpu: Send + Sync + std::fmt::Debug {
    fn cpu_type(&self) -> CpuType;
    fn ptrsize(&self) -> usize;
    fn insn_step(&self) -> usize;

    //
    // for each instruction type, the format is Vector<opcode, mask>
    //

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;

    fn name(&self) -> String {
        self.cpu_type().to_string()
    }
}

impl std::fmt::Display for CpuType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = match self {
            CpuType::X86 => "x86-32",
            CpuType::X64 => "x86-64",
            CpuType::ARM => "ARM",
            CpuType::ARM64 => "ARM64",
        };

        write!(f, "Arch={}", val)
    }
}
