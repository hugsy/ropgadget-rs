pub mod x86;
pub mod x64;

#[derive(std::fmt::Debug)]
pub enum CpuType
{
    X86,
    X64,
    // todo: ARM, ARM64
}


pub trait Cpu
{
    fn cpu_type(&self) -> CpuType;
    fn name(&self) -> &str;
    fn ptrsize(&self) -> usize;
    fn ret_insn(&self) -> Vec<u8>;
}


impl std::fmt::Display for CpuType
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let val = match self
        {
            CpuType::X86 => {"x86-32"}
            CpuType::X64 => {"x86-64"}
        };

        write!(f, "Arch={}", val)
    }
}