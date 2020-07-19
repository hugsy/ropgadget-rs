use crate::cpu;


pub struct X86 {}


impl cpu::Cpu for X86
{
    fn cpu_type(&self) -> cpu::CpuType
    {
        cpu::CpuType::X86
    }


    fn name(&self) -> &str
    {
        "x86"
    }


    fn ptrsize(&self) -> usize
    {
        4
    }


    fn ret_insn(&self) -> Vec<u8>
    {
        vec![0xc3]
    }
}
