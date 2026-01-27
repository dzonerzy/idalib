use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};

use crate::ffi::BADADDR;
use crate::ffi::bytes::{
    get_flags, idalib_get_byte, idalib_get_bytes, idalib_get_dword, idalib_get_qword,
    idalib_get_word, patch_byte, patch_bytes, patch_dword, patch_qword, patch_word,
};
use crate::ffi::comments::{append_cmt, idalib_get_cmt, set_cmt};
use crate::ffi::conversions::idalib_ea2str;
use crate::ffi::entry::{get_entry, get_entry_ordinal, get_entry_qty};
use crate::ffi::func::{
    add_func, del_func, get_func, get_func_qty, getn_func, idalib_get_func_cmt, idalib_set_func_cmt,
};
use crate::ffi::hexrays::{decompile_func, init_hexrays_plugin, term_hexrays_plugin};
use crate::ffi::ida::{
    auto_wait, close_database_with, make_signatures, open_database_quiet, set_screen_ea,
};
use crate::ffi::insn::{decode, idalib_print_insn_mnem, idalib_print_operand};
use crate::ffi::loader::find_plugin;
use crate::ffi::name::set_name;
use crate::ffi::processor::get_ph;
use crate::ffi::search::{idalib_find_defined, idalib_find_imm, idalib_find_text};
use crate::ffi::segment::{get_segm_by_name, get_segm_qty, getnseg, getseg};
use crate::ffi::typeinf::{
    // UDT creation and modification
    idalib_add_udt_member,
    // Basic type operations
    idalib_apply_cdecl,
    // Named type operations
    idalib_apply_named_type,
    idalib_create_udt,
    idalib_del_type,
    idalib_del_udt_member,
    idalib_del_udt_members,
    // Named UDT operations
    idalib_find_named_udt_member_by_name,
    idalib_find_named_udt_member_by_offset,
    // UDT (struct/union) operations
    idalib_find_udt_member_by_name,
    idalib_find_udt_member_by_offset,
    // Enum operations
    idalib_get_enum_member_count,
    idalib_get_enum_member_info,
    idalib_get_func_prototype,
    // Type library operations
    idalib_get_loaded_tils,
    idalib_get_named_enum_member_count,
    idalib_get_named_enum_member_info,
    idalib_get_named_type,
    idalib_get_named_type_size,
    idalib_get_named_type_tid,
    idalib_get_named_udt_member_count,
    idalib_get_named_udt_member_info,
    idalib_get_named_udt_size,
    // Numbered type (ordinal) operations
    idalib_get_numbered_type,
    idalib_get_numbered_type_name,
    idalib_get_op_type_str,
    idalib_get_ordinal_count,
    idalib_get_type_size,
    idalib_get_type_str,
    // Struct field xrefs
    idalib_get_type_xrefs,
    idalib_get_udt_member_count,
    idalib_get_udt_member_info,
    idalib_get_udt_member_tid,
    idalib_get_udt_member_xrefs,
    idalib_get_udt_size,
    idalib_has_named_type,
    idalib_has_type,
    idalib_import_type_library,
    idalib_is_array_type,
    idalib_is_enum_type,
    idalib_is_func_type,
    idalib_is_named_udt_union,
    idalib_is_ptr_type,
    idalib_is_struct_type,
    idalib_is_udt_union,
    idalib_parse_decl,
    idalib_print_type,
};
use crate::ffi::util::{is_align_insn, next_head, prev_head, str2reg};
use crate::ffi::xref::{xrefblk_t, xrefblk_t_first_from, xrefblk_t_first_to};

use crate::bookmarks::Bookmarks;
use crate::decompiler::CFunction;
use crate::func::{Function, FunctionId};
use crate::insn::{Insn, Register};
use crate::meta::{Metadata, MetadataMut};
use crate::name::NameList;
use crate::plugin::Plugin;
use crate::processor::Processor;
use crate::segment::{Segment, SegmentId};
use crate::strings::StringList;
use crate::xref::{XRef, XRefQuery};
use crate::{Address, AddressFlags, IDAError, IDARuntimeHandle, prepare_library};

pub struct IDB {
    path: PathBuf,
    save: bool,
    decompiler: bool,
    _guard: IDARuntimeHandle,
    _marker: PhantomData<*const ()>,
}

#[derive(Debug, Clone)]
pub struct IDBOpenOptions {
    idb: Option<PathBuf>,
    ftype: Option<String>,

    save: bool,
    auto_analyse: bool,
}

impl Default for IDBOpenOptions {
    fn default() -> Self {
        Self {
            idb: None,
            ftype: None,
            save: false,
            auto_analyse: true,
        }
    }
}

impl IDBOpenOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn idb(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.idb = Some(path.as_ref().to_owned());
        self
    }

    pub fn save(&mut self, save: bool) -> &mut Self {
        self.save = save;
        self
    }

    pub fn file_type(&mut self, ftype: impl AsRef<str>) -> &mut Self {
        self.ftype = Some(ftype.as_ref().to_owned());
        self
    }

    pub fn auto_analyse(&mut self, auto_analyse: bool) -> &mut Self {
        self.auto_analyse = auto_analyse;
        self
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<IDB, IDAError> {
        let mut args = Vec::new();

        if let Some(ftype) = self.ftype.as_ref() {
            args.push(format!("-T{ftype}"));
        }

        if let Some(idb_path) = self.idb.as_ref() {
            args.push("-c".to_owned());
            args.push(format!("-o{}", idb_path.display()));
        }

        IDB::open_full_with(path, self.auto_analyse, self.save, &args)
    }
}

impl IDB {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IDAError> {
        Self::open_with(path, true, false)
    }

    pub fn open_with(
        path: impl AsRef<Path>,
        auto_analyse: bool,
        save: bool,
    ) -> Result<Self, IDAError> {
        Self::open_full_with(path, auto_analyse, save, &[] as &[&str])
    }

    fn open_full_with(
        path: impl AsRef<Path>,
        auto_analyse: bool,
        save: bool,
        args: &[impl AsRef<str>],
    ) -> Result<Self, IDAError> {
        let _guard = prepare_library();
        let path = path.as_ref();

        if !path.exists() || !path.is_file() {
            return Err(IDAError::not_found(path));
        }

        open_database_quiet(path, auto_analyse, args)?;

        let decompiler = unsafe { init_hexrays_plugin(0.into()) };

        Ok(Self {
            path: path.to_owned(),
            save,
            decompiler,
            _guard,
            _marker: PhantomData,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_on_close(&mut self, status: bool) {
        self.save = status;
    }

    pub fn auto_wait(&mut self) -> bool {
        unsafe { auto_wait() }
    }

    pub fn set_screen_address(&mut self, ea: Address) {
        set_screen_ea(ea.into());
    }

    pub fn make_signatures(&mut self, only_pat: bool) -> Result<(), IDAError> {
        make_signatures(only_pat)
    }

    pub fn decompiler_available(&self) -> bool {
        self.decompiler
    }

    pub fn meta(&self) -> Metadata<'_> {
        Metadata::new()
    }

    pub fn meta_mut(&mut self) -> MetadataMut<'_> {
        MetadataMut::new()
    }

    pub fn processor(&self) -> Processor<'_> {
        let ptr = unsafe { get_ph() };
        Processor::from_ptr(ptr)
    }

    pub fn entries(&self) -> EntryPointIter<'_> {
        let limit = unsafe { get_entry_qty() };
        EntryPointIter {
            index: 0,
            limit,
            _marker: PhantomData,
        }
    }

    pub fn function_at(&self, ea: Address) -> Option<Function<'_>> {
        let ptr = unsafe { get_func(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn next_head(&self, ea: Address) -> Option<Address> {
        self.next_head_with(ea, BADADDR.into())
    }

    pub fn next_head_with(&self, ea: Address, max_ea: Address) -> Option<Address> {
        let next = unsafe { next_head(ea.into(), max_ea.into()) };
        if next == BADADDR {
            None
        } else {
            Some(next.into())
        }
    }

    pub fn prev_head(&self, ea: Address) -> Option<Address> {
        self.prev_head_with(ea, 0)
    }

    pub fn prev_head_with(&self, ea: Address, min_ea: Address) -> Option<Address> {
        let prev = unsafe { prev_head(ea.into(), min_ea.into()) };
        if prev == BADADDR {
            None
        } else {
            Some(prev.into())
        }
    }

    pub fn insn_at(&self, ea: Address) -> Option<Insn> {
        let insn = decode(ea.into())?;
        Some(Insn::from_repr(insn))
    }

    /// Get the instruction mnemonic at the given address (e.g., "mov", "call", "push")
    ///
    /// Returns an empty string if no instruction exists at the address.
    pub fn insn_mnemonic(&self, ea: Address) -> String {
        unsafe { idalib_print_insn_mnem(ea.into()) }
    }

    /// Get the string representation of an operand at the given address
    ///
    /// # Arguments
    /// * `ea` - The address of the instruction
    /// * `n` - The operand index (0-based)
    ///
    /// Returns an empty string if the operand doesn't exist or can't be formatted.
    pub fn insn_operand(&self, ea: Address, n: usize) -> String {
        unsafe { idalib_print_operand(ea.into(), autocxx::c_int(n as i32)) }
    }

    // =========================================================================
    // Type System
    // =========================================================================

    /// Get the type string at an address (e.g., "int", "char *", "struct foo")
    ///
    /// Returns an empty string if no type is defined at the address.
    pub fn get_type(&self, ea: Address) -> String {
        unsafe { idalib_get_type_str(ea.into()) }
    }

    /// Get the type of an operand at an address
    ///
    /// Returns an empty string if no type is defined for the operand.
    pub fn get_operand_type(&self, ea: Address, n: usize) -> String {
        unsafe { idalib_get_op_type_str(ea.into(), autocxx::c_int(n as i32)) }
    }

    /// Print the type at an address with optional formatting flags
    ///
    /// # Arguments
    /// * `ea` - The address
    /// * `flags` - Formatting flags (0 for default single-line output)
    pub fn print_type(&self, ea: Address, flags: i32) -> String {
        unsafe { idalib_print_type(ea.into(), autocxx::c_int(flags)) }
    }

    /// Check if a type is defined at an address
    pub fn has_type(&self, ea: Address) -> bool {
        unsafe { idalib_has_type(ea.into()) }
    }

    /// Delete the type at an address
    pub fn del_type(&self, ea: Address) {
        unsafe { idalib_del_type(ea.into()) }
    }

    /// Parse a C declaration and apply it to an address
    ///
    /// # Arguments
    /// * `ea` - The address to apply the type to
    /// * `decl` - C declaration string (e.g., "int foo" or "void __stdcall func(int x)")
    ///
    /// Returns true on success.
    pub fn apply_type(&self, ea: Address, decl: &str) -> bool {
        let c_decl = match CString::new(decl) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { idalib_apply_cdecl(ea.into(), c_decl.as_ptr()) }
    }

    /// Parse a C declaration and return the resulting type string
    ///
    /// This is useful for validating type strings without applying them.
    pub fn parse_type(&self, decl: &str) -> String {
        let c_decl = match CString::new(decl) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };
        unsafe { idalib_parse_decl(c_decl.as_ptr()) }
    }

    /// Get the size of a type at an address (in bytes)
    ///
    /// Returns 0 if no type is defined.
    pub fn get_type_size(&self, ea: Address) -> u64 {
        unsafe { idalib_get_type_size(ea.into()) }
    }

    /// Check if the type at an address is a pointer
    pub fn is_ptr_type(&self, ea: Address) -> bool {
        unsafe { idalib_is_ptr_type(ea.into()) }
    }

    /// Check if the type at an address is a function
    pub fn is_func_type(&self, ea: Address) -> bool {
        unsafe { idalib_is_func_type(ea.into()) }
    }

    /// Check if the type at an address is a struct or union
    pub fn is_struct_type(&self, ea: Address) -> bool {
        unsafe { idalib_is_struct_type(ea.into()) }
    }

    /// Check if the type at an address is an array
    pub fn is_array_type(&self, ea: Address) -> bool {
        unsafe { idalib_is_array_type(ea.into()) }
    }

    /// Check if the type at an address is an enum
    pub fn is_enum_type(&self, ea: Address) -> bool {
        unsafe { idalib_is_enum_type(ea.into()) }
    }

    /// Get the function prototype as a string (for function addresses)
    pub fn get_func_prototype(&self, ea: Address) -> String {
        unsafe { idalib_get_func_prototype(ea.into()) }
    }

    // =========================================================================
    // Named Type Operations
    // =========================================================================

    /// Apply a named type from the type library to an address
    ///
    /// # Arguments
    /// * `ea` - The address to apply the type to
    /// * `name` - Name of the type in the type library (e.g., "SOCKET", "HANDLE", "FILE")
    ///
    /// Returns true on success.
    pub fn apply_named_type(&self, ea: Address, name: &str) -> bool {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { idalib_apply_named_type(ea.into(), c_name.as_ptr()) }
    }

    /// Get a named type from the type library and return its string representation
    ///
    /// Returns an empty string if the type is not found.
    pub fn get_named_type(&self, name: &str) -> String {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };
        unsafe { idalib_get_named_type(c_name.as_ptr()) }
    }

    /// Check if a named type exists in the type library
    pub fn has_named_type(&self, name: &str) -> bool {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { idalib_has_named_type(c_name.as_ptr()) }
    }

    /// Get the size of a named type in bytes
    ///
    /// Returns 0 if the type is not found.
    pub fn get_named_type_size(&self, name: &str) -> u64 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        unsafe { idalib_get_named_type_size(c_name.as_ptr()) }
    }

    /// Get the TID (type ID) for a named type
    ///
    /// Returns BADADDR if not found.
    pub fn get_named_type_tid(&self, name: &str) -> u64 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return u64::MAX,
        };
        unsafe { idalib_get_named_type_tid(c_name.as_ptr()) }
    }

    // =========================================================================
    // Numbered Type (Ordinal) Operations
    // =========================================================================

    /// Get the number of local types in the database
    pub fn get_local_type_count(&self) -> u32 {
        unsafe { idalib_get_ordinal_count() }
    }

    /// Get a local type by its ordinal number
    ///
    /// Returns an empty string if the ordinal is invalid.
    pub fn get_local_type(&self, ordinal: u32) -> String {
        unsafe { idalib_get_numbered_type(ordinal) }
    }

    /// Get the name of a local type by its ordinal number
    ///
    /// Returns an empty string if the ordinal is invalid.
    pub fn get_local_type_name(&self, ordinal: u32) -> String {
        unsafe { idalib_get_numbered_type_name(ordinal) }
    }

    // =========================================================================
    // UDT (Struct/Union) Operations at Address
    // =========================================================================

    /// Get the number of members in a struct/union at an address
    ///
    /// Returns -1 if no struct/union type is defined at the address.
    pub fn get_udt_member_count(&self, ea: Address) -> i32 {
        unsafe { idalib_get_udt_member_count(ea.into()) }
    }

    /// Get information about a UDT member by index
    ///
    /// Returns a tuple of (name, type_str, offset, size) or None if not found.
    pub fn get_udt_member(&self, ea: Address, index: u32) -> Option<(String, String, u64, u64)> {
        let info = unsafe { idalib_get_udt_member_info(ea.into(), index) };
        if info.is_empty() {
            return None;
        }
        // Parse "name|type|offset|size"
        let parts: Vec<&str> = info.split('|').collect();
        if parts.len() != 4 {
            return None;
        }
        let offset = parts[2].parse().ok()?;
        let size = parts[3].parse().ok()?;
        Some((parts[0].to_string(), parts[1].to_string(), offset, size))
    }

    /// Get the total size of a UDT at an address in bytes
    ///
    /// Returns 0 if no UDT is defined at the address.
    pub fn get_udt_size(&self, ea: Address) -> u64 {
        unsafe { idalib_get_udt_size(ea.into()) }
    }

    /// Check if the UDT at an address is a union (vs struct)
    pub fn is_udt_union(&self, ea: Address) -> bool {
        unsafe { idalib_is_udt_union(ea.into()) }
    }

    /// Find a UDT member by name and return its index
    ///
    /// Returns -1 if not found.
    pub fn find_udt_member_by_name(&self, ea: Address, name: &str) -> i32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        unsafe { idalib_find_udt_member_by_name(ea.into(), c_name.as_ptr()) }
    }

    /// Find the UDT member at a given byte offset and return its index
    ///
    /// Returns -1 if not found.
    pub fn find_udt_member_by_offset(&self, ea: Address, offset: u64) -> i32 {
        unsafe { idalib_find_udt_member_by_offset(ea.into(), offset) }
    }

    // =========================================================================
    // Named UDT Operations (by type name)
    // =========================================================================

    /// Get the number of members in a named struct/union
    ///
    /// Returns -1 if the type is not found or is not a UDT.
    pub fn get_named_udt_member_count(&self, name: &str) -> i32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        unsafe { idalib_get_named_udt_member_count(c_name.as_ptr()) }
    }

    /// Get information about a named UDT member by index
    ///
    /// Returns a tuple of (name, type_str, offset, size) or None if not found.
    pub fn get_named_udt_member(
        &self,
        udt_name: &str,
        index: u32,
    ) -> Option<(String, String, u64, u64)> {
        let c_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let info = unsafe { idalib_get_named_udt_member_info(c_name.as_ptr(), index) };
        if info.is_empty() {
            return None;
        }
        // Parse "name|type|offset|size"
        let parts: Vec<&str> = info.split('|').collect();
        if parts.len() != 4 {
            return None;
        }
        let offset = parts[2].parse().ok()?;
        let size = parts[3].parse().ok()?;
        Some((parts[0].to_string(), parts[1].to_string(), offset, size))
    }

    /// Get the total size of a named UDT in bytes
    ///
    /// Returns 0 if the type is not found or is not a UDT.
    pub fn get_named_udt_size(&self, name: &str) -> u64 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        unsafe { idalib_get_named_udt_size(c_name.as_ptr()) }
    }

    /// Check if a named type is a union (vs struct)
    pub fn is_named_udt_union(&self, name: &str) -> bool {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { idalib_is_named_udt_union(c_name.as_ptr()) }
    }

    /// Find a member by name in a named UDT and return its index
    ///
    /// Returns -1 if not found.
    pub fn find_named_udt_member_by_name(&self, udt_name: &str, member_name: &str) -> i32 {
        let c_udt_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let c_member_name = match CString::new(member_name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        unsafe { idalib_find_named_udt_member_by_name(c_udt_name.as_ptr(), c_member_name.as_ptr()) }
    }

    /// Find a member by offset in a named UDT and return its index
    ///
    /// Returns -1 if not found.
    pub fn find_named_udt_member_by_offset(&self, name: &str, offset: u64) -> i32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        unsafe { idalib_find_named_udt_member_by_offset(c_name.as_ptr(), offset) }
    }

    // =========================================================================
    // Enum Operations
    // =========================================================================

    /// Get the number of members in an enum at an address
    ///
    /// Returns -1 if no enum type is defined at the address.
    pub fn get_enum_member_count(&self, ea: Address) -> i32 {
        unsafe { idalib_get_enum_member_count(ea.into()) }
    }

    /// Get enum member info by index
    ///
    /// Returns a tuple of (name, value) or None if not found.
    pub fn get_enum_member(&self, ea: Address, index: u32) -> Option<(String, u64)> {
        let info = unsafe { idalib_get_enum_member_info(ea.into(), index) };
        if info.is_empty() {
            return None;
        }
        // Parse "name|value"
        let parts: Vec<&str> = info.split('|').collect();
        if parts.len() != 2 {
            return None;
        }
        let value = parts[1].parse().ok()?;
        Some((parts[0].to_string(), value))
    }

    /// Get the number of members in a named enum
    ///
    /// Returns -1 if the type is not found or is not an enum.
    pub fn get_named_enum_member_count(&self, name: &str) -> i32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        unsafe { idalib_get_named_enum_member_count(c_name.as_ptr()) }
    }

    /// Get named enum member info by index
    ///
    /// Returns a tuple of (name, value) or None if not found.
    pub fn get_named_enum_member(&self, enum_name: &str, index: u32) -> Option<(String, u64)> {
        let c_name = match CString::new(enum_name) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let info = unsafe { idalib_get_named_enum_member_info(c_name.as_ptr(), index) };
        if info.is_empty() {
            return None;
        }
        // Parse "name|value"
        let parts: Vec<&str> = info.split('|').collect();
        if parts.len() != 2 {
            return None;
        }
        let value = parts[1].parse().ok()?;
        Some((parts[0].to_string(), value))
    }

    // =========================================================================
    // Type Library Operations
    // =========================================================================

    /// Import a type library (.til file)
    ///
    /// # Arguments
    /// * `tilname` - Name of the type library (e.g., "mssdk_win10", "gnulnx_x64")
    ///
    /// Returns true on success.
    pub fn import_type_library(&self, tilname: &str) -> bool {
        let c_name = match CString::new(tilname) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { idalib_import_type_library(c_name.as_ptr()) }
    }

    /// Get a list of loaded type libraries
    ///
    /// Returns a vector of type library names.
    pub fn get_loaded_type_libraries(&self) -> Vec<String> {
        let tils = unsafe { idalib_get_loaded_tils() };
        if tils.is_empty() {
            return Vec::new();
        }
        tils.split(';').map(|s| s.to_string()).collect()
    }

    // =========================================================================
    // UDT (Struct/Union) Creation and Modification
    // =========================================================================

    /// Create a new struct or union in the local type library
    ///
    /// # Arguments
    /// * `name` - Name of the new struct/union
    /// * `is_union` - true for union, false for struct
    ///
    /// Returns the ordinal of the new type, or 0 on failure.
    pub fn create_struct(&self, name: &str, is_union: bool) -> u32 {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        unsafe { idalib_create_udt(c_name.as_ptr(), is_union) }
    }

    /// Add a member to a struct or union
    ///
    /// # Arguments
    /// * `udt_name` - Name of the struct/union to modify
    /// * `member_name` - Name of the new member
    /// * `member_type` - C type declaration (e.g., "int", "char *", "unsigned long")
    /// * `offset` - Byte offset for the member, or None for auto-placement at end
    ///
    /// Returns 0 (TERR_OK) on success, negative error code on failure.
    pub fn add_struct_member(
        &self,
        udt_name: &str,
        member_name: &str,
        member_type: &str,
        offset: Option<i64>,
    ) -> i32 {
        let c_udt = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return -5, // TERR_BAD_TYPE
        };
        let c_member = match CString::new(member_name) {
            Ok(s) => s,
            Err(_) => return -3, // TERR_BAD_NAME
        };
        let c_type = match CString::new(member_type) {
            Ok(s) => s,
            Err(_) => return -5, // TERR_BAD_TYPE
        };
        unsafe {
            idalib_add_udt_member(
                c_udt.as_ptr(),
                c_member.as_ptr(),
                c_type.as_ptr(),
                offset.unwrap_or(-1),
            )
        }
    }

    /// Delete a member from a struct or union by index
    ///
    /// # Arguments
    /// * `udt_name` - Name of the struct/union to modify
    /// * `member_index` - Index of the member to delete
    ///
    /// Returns 0 (TERR_OK) on success, negative error code on failure.
    pub fn del_struct_member(&self, udt_name: &str, member_index: u32) -> i32 {
        let c_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return -5, // TERR_BAD_TYPE
        };
        unsafe { idalib_del_udt_member(c_name.as_ptr(), member_index) }
    }

    /// Delete multiple members from a struct or union by index range
    ///
    /// # Arguments
    /// * `udt_name` - Name of the struct/union to modify
    /// * `start_index` - First member to delete (inclusive)
    /// * `end_index` - Last member to delete (exclusive)
    ///
    /// Returns 0 (TERR_OK) on success, negative error code on failure.
    pub fn del_struct_members(&self, udt_name: &str, start_index: u32, end_index: u32) -> i32 {
        let c_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return -5, // TERR_BAD_TYPE
        };
        unsafe { idalib_del_udt_members(c_name.as_ptr(), start_index, end_index) }
    }

    // =========================================================================
    // Struct Field XRefs
    // =========================================================================

    /// Get the TID (type ID) for a struct/union member
    ///
    /// This TID can be used to find xrefs to the member.
    ///
    /// # Arguments
    /// * `udt_name` - Name of the struct/union
    /// * `member_index` - Index of the member
    ///
    /// Returns the TID, or None if not found.
    pub fn get_struct_member_tid(&self, udt_name: &str, member_index: u32) -> Option<u64> {
        let c_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let tid = unsafe { idalib_get_udt_member_tid(c_name.as_ptr(), member_index) };
        if tid == u64::MAX { None } else { Some(tid) }
    }

    /// Get cross-references to a struct/union member
    ///
    /// # Arguments
    /// * `udt_name` - Name of the struct/union
    /// * `member_index` - Index of the member
    ///
    /// Returns a vector of addresses that reference this member.
    pub fn get_struct_member_xrefs(&self, udt_name: &str, member_index: u32) -> Vec<Address> {
        let c_name = match CString::new(udt_name) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let xrefs = unsafe { idalib_get_udt_member_xrefs(c_name.as_ptr(), member_index) };
        if xrefs.is_empty() {
            return Vec::new();
        }
        xrefs
            .split(';')
            .filter_map(|s| {
                let s = s.trim_start_matches("0x");
                u64::from_str_radix(s, 16).ok()
            })
            .collect()
    }

    /// Get cross-references to a named type (struct/union/enum)
    ///
    /// # Arguments
    /// * `type_name` - Name of the type
    ///
    /// Returns a vector of addresses that reference this type.
    pub fn get_type_xrefs(&self, type_name: &str) -> Vec<Address> {
        let c_name = match CString::new(type_name) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let xrefs = unsafe { idalib_get_type_xrefs(c_name.as_ptr()) };
        if xrefs.is_empty() {
            return Vec::new();
        }
        xrefs
            .split(';')
            .filter_map(|s| {
                let s = s.trim_start_matches("0x");
                u64::from_str_radix(s, 16).ok()
            })
            .collect()
    }

    pub fn decompile<'a>(&'a self, f: &Function<'a>) -> Result<CFunction<'a>, IDAError> {
        self.decompile_with(f, false)
    }

    pub fn decompile_with<'a>(
        &'a self,
        f: &Function<'a>,
        all_blocks: bool,
    ) -> Result<CFunction<'a>, IDAError> {
        if !self.decompiler {
            return Err(IDAError::ffi_with("no decompiler available"));
        }

        Ok(unsafe {
            decompile_func(f.as_ptr(), all_blocks)
                .map(|f| CFunction::new(f).expect("null pointer checked"))?
        })
    }

    pub fn function_by_id(&self, id: FunctionId) -> Option<Function<'_>> {
        let ptr = unsafe { getn_func(id) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn functions<'a>(&'a self) -> impl Iterator<Item = (FunctionId, Function<'a>)> + 'a {
        (0..self.function_count()).filter_map(|id| self.function_by_id(id).map(|f| (id, f)))
    }

    pub fn function_count(&self) -> usize {
        unsafe { get_func_qty() }
    }

    pub fn segment_at(&self, ea: Address) -> Option<Segment<'_>> {
        let ptr = unsafe { getseg(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segment_by_id(&self, id: SegmentId) -> Option<Segment<'_>> {
        let ptr = unsafe { getnseg((id as i32).into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segment_by_name(&self, name: impl AsRef<str>) -> Option<Segment<'_>> {
        let s = CString::new(name.as_ref()).ok()?;
        let ptr = unsafe { get_segm_by_name(s.as_ptr()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segments<'a>(&'a self) -> impl Iterator<Item = (SegmentId, Segment<'a>)> + 'a {
        (0..self.segment_count()).filter_map(|id| self.segment_by_id(id).map(|s| (id, s)))
    }

    pub fn segment_count(&self) -> usize {
        unsafe { get_segm_qty().0 as _ }
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Register> {
        let s = CString::new(name.as_ref()).ok()?;
        let id = unsafe { str2reg(s.as_ptr()).0 };

        if id == -1 { None } else { Some(id as _) }
    }

    pub fn insn_alignment_at(&self, ea: Address) -> Option<usize> {
        let align = unsafe { is_align_insn(ea.into()).0 };
        if align == 0 { None } else { Some(align as _) }
    }

    pub fn first_xref_from(&self, ea: Address, flags: XRefQuery) -> Option<XRef<'_>> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_from(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn first_xref_to(&self, ea: Address, flags: XRefQuery) -> Option<XRef<'_>> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_to(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn get_cmt(&self, ea: Address) -> Option<String> {
        self.get_cmt_with(ea, false)
    }

    pub fn get_cmt_with(&self, ea: Address, rptble: bool) -> Option<String> {
        let s = unsafe { idalib_get_cmt(ea.into(), rptble) };

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn get_func_cmt(&self, ea: Address) -> Option<String> {
        self.get_func_cmt_with(ea, false)
    }

    pub fn get_func_cmt_with(&self, ea: Address, rptble: bool) -> Option<String> {
        let f = self.function_at(ea)?;
        let s = unsafe { idalib_get_func_cmt(f.as_ptr() as _, rptble) }.ok()?;

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn set_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.set_cmt_with(ea, comm, false)
    }

    pub fn set_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { set_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set comment at {ea:#x}"
            )))
        }
    }

    pub fn set_func_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.set_func_cmt_with(ea, comm, false)
    }

    pub fn set_func_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let f = self
            .function_at(ea)
            .ok_or_else(|| IDAError::ffi_with(format!("no function found at address {ea:#x}")))?;
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { idalib_set_func_cmt(f.as_ptr() as _, s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set function comment at {ea:#x}"
            )))
        }
    }

    pub fn append_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.append_cmt_with(ea, comm, false)
    }

    pub fn append_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { append_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to append comment at {ea:#x}"
            )))
        }
    }

    pub fn remove_cmt(&self, ea: Address) -> Result<(), IDAError> {
        self.remove_cmt_with(ea, false)
    }

    pub fn remove_cmt_with(&self, ea: Address, rptble: bool) -> Result<(), IDAError> {
        if unsafe { set_cmt(ea.into(), c"".as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to remove comment at {ea:#x}"
            )))
        }
    }

    pub fn remove_func_cmt(&self, ea: Address) -> Result<(), IDAError> {
        self.remove_func_cmt_with(ea, false)
    }

    pub fn remove_func_cmt_with(&self, ea: Address, rptble: bool) -> Result<(), IDAError> {
        let f = self
            .function_at(ea)
            .ok_or_else(|| IDAError::ffi_with(format!("no function found at address {ea:#x}")))?;
        if unsafe { idalib_set_func_cmt(f.as_ptr(), c"".as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to remove comment at {ea:#x}"
            )))
        }
    }

    pub fn bookmarks(&self) -> Bookmarks<'_> {
        Bookmarks::new(self)
    }

    pub fn find_text(&self, start_ea: Address, text: impl AsRef<str>) -> Option<Address> {
        let s = CString::new(text.as_ref()).ok()?;
        let addr = unsafe { idalib_find_text(start_ea.into(), s.as_ptr()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_text_iter<'a, T>(&'a self, text: T) -> impl Iterator<Item = Address> + 'a
    where
        T: AsRef<str> + 'a,
    {
        let mut cur = 0u64;
        std::iter::from_fn(move || {
            let found = self.find_text(cur, text.as_ref())?;
            cur = self.find_defined(found).unwrap_or(BADADDR.into());
            Some(found)
        })
    }

    pub fn find_imm(&self, start_ea: Address, imm: u32) -> Option<Address> {
        let addr = unsafe { idalib_find_imm(start_ea.into(), imm.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_imm_iter<'a>(&'a self, imm: u32) -> impl Iterator<Item = Address> + 'a {
        let mut cur = 0u64;
        std::iter::from_fn(move || {
            cur = self.find_imm(cur, imm)?;
            Some(cur)
        })
    }

    pub fn find_defined(&self, start_ea: Address) -> Option<Address> {
        let addr = unsafe { idalib_find_defined(start_ea.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn strings(&self) -> StringList<'_> {
        StringList::new(self)
    }

    pub fn names(&self) -> crate::name::NameList<'_> {
        NameList::new(self)
    }

    pub fn address_to_string(&self, ea: Address) -> Option<String> {
        let s = unsafe { idalib_ea2str(ea.into()) };

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn flags_at(&self, ea: Address) -> AddressFlags<'_> {
        AddressFlags::new(unsafe { get_flags(ea.into()) })
    }

    pub fn get_byte(&self, ea: Address) -> u8 {
        unsafe { idalib_get_byte(ea.into()) }
    }

    pub fn get_word(&self, ea: Address) -> u16 {
        unsafe { idalib_get_word(ea.into()) }
    }

    pub fn get_dword(&self, ea: Address) -> u32 {
        unsafe { idalib_get_dword(ea.into()) }
    }

    pub fn get_qword(&self, ea: Address) -> u64 {
        unsafe { idalib_get_qword(ea.into()) }
    }

    pub fn get_bytes(&self, ea: Address, size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size);

        let Ok(new_len) = (unsafe { idalib_get_bytes(ea.into(), &mut buf) }) else {
            return Vec::with_capacity(0);
        };

        unsafe {
            buf.set_len(new_len);
        }

        buf
    }

    // =========================================================================
    // Patching / Writing bytes
    // =========================================================================

    /// Patch a single byte at the given address.
    ///
    /// Returns `true` if the patch was successful.
    pub fn patch_byte(&self, ea: Address, value: u8) -> bool {
        use autocxx::prelude::*;
        unsafe { patch_byte(ea.into(), c_ulonglong(value as u64)) }
    }

    /// Patch a 16-bit word at the given address.
    ///
    /// Returns `true` if the patch was successful.
    pub fn patch_word(&self, ea: Address, value: u16) -> bool {
        use autocxx::prelude::*;
        unsafe { patch_word(ea.into(), c_ulonglong(value as u64)) }
    }

    /// Patch a 32-bit dword at the given address.
    ///
    /// Returns `true` if the patch was successful.
    pub fn patch_dword(&self, ea: Address, value: u32) -> bool {
        use autocxx::prelude::*;
        unsafe { patch_dword(ea.into(), c_ulonglong(value as u64)) }
    }

    /// Patch a 64-bit qword at the given address.
    ///
    /// Returns `true` if the patch was successful.
    pub fn patch_qword(&self, ea: Address, value: u64) -> bool {
        use autocxx::prelude::*;
        unsafe { patch_qword(ea.into(), c_ulonglong(value)) }
    }

    /// Patch multiple bytes at the given address.
    pub fn patch_bytes(&self, ea: Address, bytes: &[u8]) {
        use autocxx::prelude::*;
        unsafe { patch_bytes(ea.into(), bytes.as_ptr() as *const c_void, bytes.len()) }
    }

    // =========================================================================
    // Naming
    // =========================================================================

    /// Set a name at the given address.
    ///
    /// Returns `true` if the name was successfully set.
    ///
    /// # Arguments
    /// * `ea` - The address to name
    /// * `name` - The new name
    /// * `flags` - Flags controlling the naming behavior (use `SetNameFlags` from `name` module)
    pub fn set_name(&self, ea: Address, name: &str, flags: i32) -> bool {
        use autocxx::prelude::*;
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return false,
        };
        unsafe { set_name(ea.into(), c_name.as_ptr(), c_int(flags)) }
    }

    /// Set a name at the given address, forcing replacement of any existing name.
    pub fn force_name(&self, ea: Address, name: &str) -> bool {
        // SN_FORCE = 0x800
        self.set_name(ea, name, 0x800)
    }

    /// Delete the name at the given address.
    pub fn delete_name(&self, ea: Address) -> bool {
        self.set_name(ea, "", 0)
    }

    // =========================================================================
    // Function management
    // =========================================================================

    /// Create a new function at the given address.
    ///
    /// IDA will automatically determine the function boundaries.
    /// Returns `true` if the function was created successfully.
    pub fn add_function(&self, ea: Address) -> bool {
        unsafe { add_func(ea.into(), BADADDR) }
    }

    /// Create a new function with explicit start and end addresses.
    ///
    /// Returns `true` if the function was created successfully.
    pub fn add_function_with_bounds(&self, start: Address, end: Address) -> bool {
        unsafe { add_func(start.into(), end.into()) }
    }

    /// Delete the function at the given address.
    ///
    /// Returns `true` if the function was deleted successfully.
    pub fn delete_function(&self, ea: Address) -> bool {
        unsafe { del_func(ea.into()) }
    }

    pub fn find_plugin(
        &self,
        name: impl AsRef<str>,
        load_if_needed: bool,
    ) -> Result<Plugin<'_>, IDAError> {
        let plugin = CString::new(name.as_ref()).map_err(IDAError::ffi)?;
        let ptr = unsafe { find_plugin(plugin.as_ptr(), load_if_needed) };

        if ptr.is_null() {
            Err(IDAError::ffi_with(format!(
                "failed to load {} plugin",
                name.as_ref()
            )))
        } else {
            Ok(Plugin::from_ptr(ptr))
        }
    }

    pub fn load_plugin(&self, name: impl AsRef<str>) -> Result<Plugin<'_>, IDAError> {
        self.find_plugin(name, true)
    }
}

impl Drop for IDB {
    fn drop(&mut self) {
        if self.decompiler {
            unsafe {
                term_hexrays_plugin();
            }
        }
        close_database_with(self.save);
    }
}

pub struct EntryPointIter<'a> {
    index: usize,
    limit: usize,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Iterator for EntryPointIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.limit {
            return None;
        }

        let ordinal = unsafe { get_entry_ordinal(self.index) };
        let addr = unsafe { get_entry(ordinal) };

        // skip?
        if addr == BADADDR {
            self.index += 1;
            return self.next();
        }

        Some(addr.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let lim = self.limit - self.index;
        (0, Some(lim))
    }
}
