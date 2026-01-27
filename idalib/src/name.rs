use std::ffi::{CStr, CString};
use std::marker::PhantomData;

use bitflags::bitflags;

use crate::ffi::BADADDR;
use crate::ffi::name::{
    SN_AUTO, SN_CHECK, SN_FORCE, SN_LOCAL, SN_NOCHECK, SN_NODUMMY, SN_NOLIST, SN_NON_AUTO,
    SN_NON_PUBLIC, SN_NON_WEAK, SN_NOWARN, SN_PUBLIC, SN_WEAK, get_nlist_ea, get_nlist_idx,
    get_nlist_name, get_nlist_size, is_in_nlist, is_public_name, is_weak_name, set_name,
};

use crate::Address;
use crate::idb::IDB;

pub type NameIndex = usize;

pub struct NameList<'a> {
    _marker: PhantomData<&'a IDB>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NameProperties: u8 {
        const PUBLIC = 0x01;
        const WEAK = 0x02;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    address: Address,
    name: String,
    index: NameIndex,
    properties: NameProperties,
}

impl Name {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_public(&self) -> bool {
        self.properties.contains(NameProperties::PUBLIC)
    }

    pub fn is_weak(&self) -> bool {
        self.properties.contains(NameProperties::WEAK)
    }
}

impl<'a> NameList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn get_by_index(&self, index: NameIndex) -> Option<Name> {
        let addr = self.get_address_by_index(index)?;
        let name = unsafe { get_nlist_name(index) };
        if name.is_null() {
            return None;
        }

        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();

        let mut properties = NameProperties::empty();

        if unsafe { is_public_name(addr.into()) } {
            properties.insert(NameProperties::PUBLIC);
        }

        if unsafe { is_weak_name(addr.into()) } {
            properties.insert(NameProperties::WEAK);
        }

        Some(Name {
            address: addr,
            name,
            index,
            properties,
        })
    }

    pub fn get_closest_by_address(&self, address: Address) -> Option<Name> {
        let index = unsafe { get_nlist_idx(address.into()) };
        self.get_by_index(index)
    }

    pub fn get_address_by_index(&self, index: NameIndex) -> Option<Address> {
        let addr = unsafe { get_nlist_ea(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn has_name(&self, address: Address) -> bool {
        unsafe { is_in_nlist(address.into()) }
    }

    pub fn len(&self) -> usize {
        unsafe { get_nlist_size() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> NameListIter<'_, 'a> {
        NameListIter {
            name_list: self,
            current_index: 0,
        }
    }
}

pub struct NameListIter<'s, 'a> {
    name_list: &'s NameList<'a>,
    current_index: NameIndex,
}

impl<'s, 'a> Iterator for NameListIter<'s, 'a> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.name_list.len() {
            let name = self.name_list.get_by_index(self.current_index);

            self.current_index += 1;

            if name.is_some() {
                return name;
            }
        }
        None
    }
}

// =============================================================================
// Name modification functions
// =============================================================================

bitflags! {
    /// Flags for the `set_name` function.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct SetNameFlags: i32 {
        /// Validate the name before storing it (check for valid characters, etc.)
        const CHECK = SN_CHECK as i32;
        /// Don't validate the name
        const NOCHECK = SN_NOCHECK as i32;
        /// Mark the name as public
        const PUBLIC = SN_PUBLIC as i32;
        /// Mark the name as non-public
        const NON_PUBLIC = SN_NON_PUBLIC as i32;
        /// Mark the name as weak
        const WEAK = SN_WEAK as i32;
        /// Mark the name as non-weak
        const NON_WEAK = SN_NON_WEAK as i32;
        /// Mark the name as auto-generated
        const AUTO = SN_AUTO as i32;
        /// Mark the name as non-auto-generated (user-defined)
        const NON_AUTO = SN_NON_AUTO as i32;
        /// Don't include the name in the name list
        const NOLIST = SN_NOLIST as i32;
        /// Don't display a warning if the name already exists
        const NOWARN = SN_NOWARN as i32;
        /// Create a local name (valid only in the current function)
        const LOCAL = SN_LOCAL as i32;
        /// Force the name (replace existing name)
        const FORCE = SN_FORCE as i32;
        /// Don't create a dummy name if the name is invalid
        const NODUMMY = SN_NODUMMY as i32;
    }
}

/// Set the name at a given address.
///
/// # Arguments
/// * `address` - The address to name
/// * `name` - The new name (empty string to delete the name)
/// * `flags` - Flags controlling the naming behavior
///
/// # Returns
/// * `true` if the name was successfully set
/// * `false` if the operation failed
///
/// # Example
/// ```ignore
/// use idalib::name::{set_name_at, SetNameFlags};
///
/// // Set a simple name
/// set_name_at(0x401000, "my_function", SetNameFlags::CHECK);
///
/// // Force rename even if name exists
/// set_name_at(0x401000, "new_name", SetNameFlags::FORCE);
///
/// // Delete a name
/// set_name_at(0x401000, "", SetNameFlags::empty());
/// ```
pub fn set_name_at(address: Address, name: &str, flags: SetNameFlags) -> bool {
    use autocxx::prelude::*;
    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { set_name(address.into(), c_name.as_ptr(), c_int(flags.bits())) }
}

/// Set the name at a given address, forcing replacement of any existing name.
///
/// This is a convenience function equivalent to `set_name_at(address, name, SetNameFlags::FORCE)`.
pub fn force_name_at(address: Address, name: &str) -> bool {
    set_name_at(address, name, SetNameFlags::FORCE)
}

/// Delete the name at a given address.
///
/// This is a convenience function equivalent to `set_name_at(address, "", SetNameFlags::empty())`.
pub fn delete_name_at(address: Address) -> bool {
    set_name_at(address, "", SetNameFlags::empty())
}
