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


    fn ret_insn(&self) -> Vec< Vec<u8> >
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
            vec![0xeb, ], // jmp/call
            vec![0xe9, ], // jmp/call
            vec![0xff, 0xff], // jmp/call
        ]
    }


    fn insn_step(&self) -> usize
    {
        1
    }

}