use std::fmt;

bitflags! {
    pub struct Permission: u8
    {
        const NONE = 0;
        const READABLE = 1;
        const WRITABLE = 2;
        const EXECUTABLE = 4;
        const ALL = Self::READABLE.bits | Self::WRITABLE.bits | Self::EXECUTABLE.bits;
    }
}

#[derive(Debug)]
pub struct Section {
    pub start_address: u64,
    pub end_address: u64,
    pub name: String,
    pub size: usize,
    pub permission: Permission,
    pub data: Vec<u8>,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Section(name='{}', start={:#x}, sz={:#x}, permission={:?})",
            self.name, self.start_address, self.size, self.permission
        )
    }
}

impl Section {
    pub fn new(start_address: u64, end_address: u64) -> Self {
        assert!(start_address < end_address);
        let sz = (end_address - start_address) as usize;
        Self {
            start_address: start_address,
            end_address: end_address,
            size: sz,
            name: String::from(""),
            permission: Permission::NONE,
            data: vec![0; sz],
        }
    }
}

impl From<&goblin::elf::section_header::SectionHeader> for Section {
    fn from(s: &goblin::elf::section_header::SectionHeader) -> Self {
        let permission: Permission;
        match s.is_writable() {
            true => {
                permission = Permission::READABLE | Permission::EXECUTABLE | Permission::WRITABLE
            }
            false => permission = Permission::READABLE | Permission::EXECUTABLE,
        };

        let start_address = s.sh_addr as u64;
        let size = s.sh_size as usize;
        let end_address = s.sh_addr + size as u64;

        Self {
            start_address,
            end_address,
            size,
            name: String::from(""),
            permission,
            data: vec![0; size],
        }
    }
}
