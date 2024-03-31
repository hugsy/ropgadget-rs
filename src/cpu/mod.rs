pub mod arm;
pub mod x86;

use clap::ValueEnum;

#[derive(std::fmt::Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CpuType {
    Unknown,
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
            CpuType::Unknown => "Unknown",
        };

        write!(f, "Arch={}", val)
    }
}

impl Default for CpuType {
    fn default() -> Self {
        CpuType::Unknown
    }
}

impl From<&goblin::elf::header::Header> for CpuType {
    fn from(value: &goblin::elf::header::Header) -> Self {
        match value.e_machine {
            goblin::elf::header::EM_386 => CpuType::X86,
            goblin::elf::header::EM_X86_64 => CpuType::X64,
            goblin::elf::header::EM_ARM => CpuType::ARM,
            goblin::elf::header::EM_AARCH64 => CpuType::ARM64,
            _ => panic!("ELF machine format is unsupported"),
        }
    }
}

impl From<&goblin::mach::header::Header> for CpuType {
    fn from(value: &goblin::mach::header::Header) -> Self {
        match value.cputype {
            goblin::mach::constants::cputype::CPU_TYPE_X86 => CpuType::X86,
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => CpuType::X64,
            goblin::mach::constants::cputype::CPU_TYPE_ARM => CpuType::ARM,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => CpuType::ARM64,
            _ => panic!("MachO is corrupted"),
        }
    }
}

impl From<&goblin::pe::header::CoffHeader> for CpuType {
    fn from(obj: &goblin::pe::header::CoffHeader) -> Self {
        match obj.machine {
            goblin::pe::header::COFF_MACHINE_X86 => CpuType::X86,
            goblin::pe::header::COFF_MACHINE_X86_64 => CpuType::X64,
            goblin::pe::header::COFF_MACHINE_ARM => CpuType::ARM,
            goblin::pe::header::COFF_MACHINE_ARMNT => CpuType::ARM,
            goblin::pe::header::COFF_MACHINE_ARM64 => CpuType::ARM64,
            _ => panic!("Unsupported format"),
        }
    }
}
