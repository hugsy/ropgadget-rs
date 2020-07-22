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


    fn ret_insn(&self) -> Vec<Vec<u8>>
    {
        vec![
            vec![0xc3, ], // ret
            vec![0xc2, ], // ret imm
            vec![0xcb, ], // retf
            vec![0xcf, ], // retf imm
        ]
    }


    fn branch_insn(&self) -> Vec<Vec<u8>>
    {
        vec![
            vec![0xff, ], // call/jmp

        ]
    }


    fn insn_step(&self) -> usize
    {
        1
    }

}
