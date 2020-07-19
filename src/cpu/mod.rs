pub mod x86;
pub mod x64;

#[derive(std::fmt::Debug)]
pub enum CpuType
{
    Unknown,
    X86,
    X64,
    // todo: X64, ARM, ARM64
}


pub trait Cpu
{
    fn cpu_type(&self) -> CpuType;
    fn name(&self) -> &str;
    fn ptrsize(&self) -> usize;
    fn ret_insn(&self) -> Vec<u8>;
}
