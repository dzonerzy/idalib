//! Import module enumeration functions

use crate::Address;
use crate::ffi::nalt::{
    idalib_get_import, idalib_get_import_count, idalib_get_import_module_name,
    idalib_get_import_module_qty, idalib_get_module_imports,
};

/// Information about a single import
#[derive(Debug, Clone)]
pub struct Import {
    /// Address of the import
    pub address: Address,
    /// Name of the imported symbol (empty if imported by ordinal only)
    pub name: String,
    /// Ordinal number
    pub ordinal: u64,
}

/// Information about an import module (DLL/library)
#[derive(Debug, Clone)]
pub struct ImportModule {
    /// Module index
    pub index: u32,
    /// Module name (e.g., "KERNEL32.dll", "libc.so.6")
    pub name: String,
    /// Number of imports from this module
    pub import_count: u32,
}

/// Get the number of import modules
pub fn get_import_module_count() -> u32 {
    unsafe { idalib_get_import_module_qty() }
}

/// Get information about an import module by index
pub fn get_import_module(index: u32) -> Option<ImportModule> {
    let name = unsafe { idalib_get_import_module_name(index) };
    if name.is_empty() {
        return None;
    }
    let import_count = unsafe { idalib_get_import_count(index) };
    Some(ImportModule {
        index,
        name,
        import_count,
    })
}

/// Get all import modules
pub fn get_import_modules() -> Vec<ImportModule> {
    let count = get_import_module_count();
    (0..count).filter_map(get_import_module).collect()
}

/// Get the number of imports from a specific module
pub fn get_module_import_count(mod_index: u32) -> u32 {
    unsafe { idalib_get_import_count(mod_index) }
}

/// Get a specific import from a module
pub fn get_import(mod_index: u32, import_index: u32) -> Option<Import> {
    let info = unsafe { idalib_get_import(mod_index, import_index) };
    if info.is_empty() {
        return None;
    }
    parse_import_info(&info)
}

/// Get all imports from a specific module
pub fn get_module_imports(mod_index: u32) -> Vec<Import> {
    let data = unsafe { idalib_get_module_imports(mod_index) };
    if data.is_empty() {
        return Vec::new();
    }

    data.lines().filter_map(parse_import_info).collect()
}

/// Get all imports from all modules
pub fn get_all_imports() -> Vec<(ImportModule, Vec<Import>)> {
    let count = get_import_module_count();
    (0..count)
        .filter_map(|i| {
            let module = get_import_module(i)?;
            let imports = get_module_imports(i);
            Some((module, imports))
        })
        .collect()
}

/// Parse import info from semicolon-separated string: address;name;ordinal
fn parse_import_info(info: &str) -> Option<Import> {
    let parts: Vec<&str> = info.split(';').collect();
    if parts.len() < 3 {
        return None;
    }

    let address: u64 = parts[0].parse().ok()?;
    let name = parts[1].to_string();
    let ordinal: u64 = parts[2].parse().ok()?;

    Some(Import {
        address: address.into(),
        name,
        ordinal,
    })
}
