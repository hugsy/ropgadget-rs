use std::fmt;

use crate::format::pe::{
    PeCharacteristics, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};

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

impl From<PeCharacteristics> for Permission {
    fn from(value: PeCharacteristics) -> Self {
        let mut perm = Permission::default();
        if value & IMAGE_SCN_MEM_READ != 0 {
            perm |= Permission::READABLE;
        }
        if value & IMAGE_SCN_MEM_WRITE != 0 {
            perm |= Permission::WRITABLE;
        }
        if value & IMAGE_SCN_MEM_EXECUTE != 0 {
            perm |= Permission::EXECUTABLE;
        }
        perm
    }
}

#[derive(Debug, Default)]
pub struct Section {
    pub start_address: u64,
    pub end_address: u64,
    pub name: Option<String>,
    pub permission: Permission,
    pub data: Vec<u8>,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Section(name='{:?}', start={:#x}, sz={:#x}, permission={:?})",
            self.name,
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

    pub fn name(self, name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            ..self
        }
    }

    pub fn data(self, data: Vec<u8>) -> Self {
        Self { data, ..self }
    }

    pub fn is_executable(&self) -> bool {
        self.permission.contains(Permission::EXECUTABLE)
    }

    pub fn is_writable(&self) -> bool {
        self.permission.contains(Permission::WRITABLE)
    }

    pub fn is_readable(&self) -> bool {
        self.permission.contains(Permission::READABLE)
    }
}

impl From<&goblin::elf::section_header::SectionHeader> for Section {
    fn from(value: &goblin::elf::section_header::SectionHeader) -> Self {
        let mut perm = Permission::NONE;

        if value.is_executable() {
            perm |= Permission::READABLE | Permission::EXECUTABLE;
        }

        if value.is_writable() {
            perm |= Permission::READABLE | Permission::WRITABLE;
        }

        let sz = value.sh_size as usize;

        Self {
            start_address: value.sh_addr,
            end_address: value.sh_addr + sz as u64,
            permission: perm,
            name: None,
            data: vec![0; sz],
        }
    }
}

impl From<&goblin::mach::segment::Segment<'_>> for Section {
    fn from(value: &goblin::mach::segment::Segment) -> Self {
        let mut perm = Permission::READABLE;

        if value.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS == 0
            || value.flags & goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS == 0
        {
            perm |= Permission::EXECUTABLE;
        }

        let section_name = match std::str::from_utf8(&value.segname) {
            Ok(v) => String::from(v).replace('\0', ""),
            Err(_) => "".to_string(),
        };

        let sz = value.vmsize as usize;

        Self {
            start_address: value.vmaddr,
            end_address: value.vmaddr + sz as u64,
            name: Some(section_name),
            permission: perm,
            data: vec![0; sz],
        }
    }
}

// impl From<&goblin::pe::section_table::SectionTable> for Section {
//     fn from(value: &goblin::pe::section_table::SectionTable) -> Self {
//         let section_name = match std::str::from_utf8(&value.name) {
//             Ok(v) => String::from(v).replace('\0', ""),
//             Err(_) => String::new(),
//         };

//         let mut perm = Permission::NONE;
//         if value.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
//             perm |= Permission::READABLE;
//         }

//         if value.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
//             perm |= Permission::WRITABLE;
//         }

//         if value.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
//             perm |= Permission::EXECUTABLE;
//         }

//         let sz = value.virtual_size as usize;

//         Self {
//             start_address: value.virtual_address as u64,
//             end_address: (value.virtual_address + value.virtual_size) as u64,
//             name: Some(section_name),
//             permission: perm,
//             data: vec![0; sz],
//         }
//     }
// }
