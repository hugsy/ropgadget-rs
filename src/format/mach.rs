use goblin::mach::Mach;



use crate::{section::Section, common::GenericResult};


///
///
///
pub fn collect_executable_sections(_path: &str, _mach: &Mach) -> GenericResult<Vec<Section>>
{
    todo!()
}