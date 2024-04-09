pub mod arm;
pub mod x86;

use clap::ValueEnum;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
pub enum CpuType {
    #[default]
    Unknown,
    X86,
    X64,
    ARM,
    ARM64,
}

impl std::fmt::Display for CpuType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

pub trait Cpu: Send + Sync {
    fn cpu_type(&self) -> CpuType;
    fn ptrsize(&self) -> usize;
    fn insn_step(&self) -> usize;
    fn max_rewind_size(&self) -> usize;

    //
    // for each instruction type, the format is Vector<opcode, mask>
    // TODO: replace with &[u8], &[u8]
    //

    fn ret_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
    fn call_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
    fn jmp_insns(&self) -> Vec<(Vec<u8>, Vec<u8>)>;

    fn name(&self) -> String {
        self.cpu_type().to_string()
    }
}

impl std::fmt::Debug for dyn Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cpu")
            .field("cpu_type", &self.cpu_type())
            .field("name", &self.name())
            .field("ptrsize", &self.ptrsize())
            .field("insn_step", &self.insn_step())
            .finish()
    }
}
