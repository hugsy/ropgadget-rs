use std::{borrow::Borrow, fmt};

bitflags! {
    #[derive(Debug)]
    pub struct Permission: u8
    {
        const NONE = 0;
        const READABLE = 1;
        const WRITABLE = 2;
        const EXECUTABLE = 4;
        const ALL = Self::READABLE.bits() | Self::WRITABLE.bits() | Self::EXECUTABLE.bits();
    }

}

impl Default for Permission {
    /// Return NONE as default
    fn default() -> Self {
        Permission::NONE
    }
}

#[derive(Debug)]
pub struct Section {
    pub start_address: u64,
    pub end_address: u64,
    pub name: Option<String>,
    pub permission: Permission,
    pub data: Vec<u8>,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = self
            .name
            .as_ref()
            .unwrap_or(String::from("N/A").borrow())
            .clone();
        write!(
            f,
            "Section(name='{}', start={:#x}, sz={:#x}, permission={:?})",
            name,
            self.start_address,
            self.size(),
            self.permission
        )
    }
}

impl Section {
    pub fn new(start_address: u64, end_address: u64) -> Self {
        assert!(start_address < end_address);
        let sz = (end_address - start_address) as usize;
        Self {
            start_address,
            end_address,
            name: None,
            permission: Permission::NONE,
            data: vec![0; sz],
        }
    }

    pub fn size(&self) -> usize {
        (self.end_address - self.start_address) as usize
    }
}

impl Default for Section {
    fn default() -> Self {
        Self {
            start_address: Default::default(),
            end_address: Default::default(),
            name: None,
            permission: Default::default(),
            data: Default::default(),
        }
    }
}

impl From<&goblin::elf::section_header::SectionHeader> for Section {
    fn from(s: &goblin::elf::section_header::SectionHeader) -> Self {
        let permission = match s.is_writable() {
            true => Permission::READABLE | Permission::EXECUTABLE | Permission::WRITABLE,
            false => Permission::READABLE | Permission::EXECUTABLE,
        };

        let start_address = s.sh_addr as u64;
        let size = s.sh_size as usize;
        let end_address = s.sh_addr + size as u64;

        Self {
            start_address,
            end_address,
            permission,
            ..Default::default()
        }
    }
}
