use crate::cpu;


pub struct X64 {}


impl cpu::Cpu for X64
{
    fn cpu_type(&self) -> cpu::CpuType
    {
        cpu::CpuType::X64
    }


    fn name(&self) -> &str
    {
        "x86-64"
    }


    fn ptrsize(&self) -> usize
    {
        8
    }


    fn ret_insn(&self) -> Vec<u8>
    {
        vec![0xc3]
    }
}