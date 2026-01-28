use std::ffi::CString;
use std::marker::PhantomData;

use crate::Address;
use crate::ffi::hexrays::{
    cblock_iter,
    cblock_t,
    cfunc_t,
    cfuncptr_t,
    cinsn_t,
    func_arg_info_t,
    idalib_hexrays_cblock_iter,
    idalib_hexrays_cblock_iter_next,
    idalib_hexrays_cblock_len,
    idalib_hexrays_cfunc_find_lvar_by_name,
    idalib_hexrays_cfunc_get_lvar,
    // lvar functions
    idalib_hexrays_cfunc_lvar_count,
    idalib_hexrays_cfunc_pseudocode,
    idalib_hexrays_cfuncptr_inner,
    idalib_hexrays_cinsn_ea,
    idalib_hexrays_cinsn_is_expr,
    idalib_hexrays_cinsn_label_num,
    idalib_hexrays_cinsn_op,
    idalib_hexrays_cinsn_opname,
    idalib_hexrays_clear_cached_cfunc,
    idalib_hexrays_del_call_type,
    idalib_hexrays_get_call_type,
    idalib_hexrays_get_func_arg,
    idalib_hexrays_get_func_arg_count,
    idalib_hexrays_get_func_cc,
    idalib_hexrays_get_func_rettype,
    // function type manipulation
    idalib_hexrays_get_func_type,
    idalib_hexrays_map_lvar,
    idalib_hexrays_rename_lvar,
    // user-defined calls
    idalib_hexrays_set_call_type,
    idalib_hexrays_set_func_arg_name,
    idalib_hexrays_set_func_arg_type,
    idalib_hexrays_set_func_cc,
    idalib_hexrays_set_func_rettype,
    idalib_hexrays_set_func_type,
    idalib_hexrays_set_lvar_cmt,
    idalib_hexrays_set_lvar_noptr,
    idalib_hexrays_set_lvar_type,
    idalib_hexrays_unmap_lvar,
    lvar_info_t,
};
use crate::idb::IDB;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

/// Information about a local variable in decompiled code
#[derive(Debug, Clone)]
pub struct LocalVariable {
    pub idx: i32,
    pub name: String,
    pub type_str: String,
    pub width: i32,
    pub defea: u64,
    pub defblk: i32,
    pub is_arg: bool,
    pub is_stk_var: bool,
    pub is_reg_var: bool,
    pub has_user_name: bool,
    pub has_user_type: bool,
    pub comment: String,
}

impl From<lvar_info_t> for LocalVariable {
    fn from(info: lvar_info_t) -> Self {
        Self {
            idx: info.idx,
            name: info.name,
            type_str: info.type_str,
            width: info.width,
            defea: info.defea,
            defblk: info.defblk,
            is_arg: info.is_arg,
            is_stk_var: info.is_stk_var,
            is_reg_var: info.is_reg_var,
            has_user_name: info.has_user_name,
            has_user_type: info.has_user_type,
            comment: info.cmt,
        }
    }
}

/// Information about a function argument
#[derive(Debug, Clone)]
pub struct FunctionArgument {
    pub idx: i32,
    pub name: String,
    pub type_str: String,
}

impl From<func_arg_info_t> for FunctionArgument {
    fn from(info: func_arg_info_t) -> Self {
        Self {
            idx: info.idx,
            name: info.name,
            type_str: info.type_str,
        }
    }
}

pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    _marker: PhantomData<&'a ()>,
}

pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

/// A decompiled C statement (cinsn_t wrapper)
pub struct CInsn<'a> {
    ptr: *mut cinsn_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CInsn<'a> {
    /// Get the statement type as a numeric value (ctype_t)
    pub fn op(&self) -> i32 {
        unsafe { idalib_hexrays_cinsn_op(self.ptr).0 }
    }

    /// Get the address associated with this statement
    pub fn address(&self) -> Address {
        unsafe { idalib_hexrays_cinsn_ea(self.ptr).0.into() }
    }

    /// Get the label number (-1 means no label)
    pub fn label_num(&self) -> i32 {
        unsafe { idalib_hexrays_cinsn_label_num(self.ptr).0 }
    }

    /// Check if this item is an expression (cot_* types) rather than a statement (cit_* types)
    pub fn is_expr(&self) -> bool {
        unsafe { idalib_hexrays_cinsn_is_expr(self.ptr) }
    }

    /// Get the statement/expression type as a human-readable string
    pub fn opname(&self) -> String {
        unsafe { idalib_hexrays_cinsn_opname(self.ptr) }
    }
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    fn as_cfunc(&self) -> &cfunc_t {
        unsafe { self.ptr.as_ref().expect("valid pointer") }
    }

    pub fn body(&self) -> CBlock<'_> {
        let cf = self.as_cfunc();
        let ptr = unsafe { cf.body.__bindgen_anon_1.cblock };

        CBlock {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Get the number of local variables in this function
    pub fn lvar_count(&self) -> usize {
        unsafe { idalib_hexrays_cfunc_lvar_count(self.ptr) }
    }

    /// Get a local variable by index
    pub fn get_lvar(&self, idx: usize) -> Option<LocalVariable> {
        let mut info = lvar_info_t::default();
        let ok = unsafe { idalib_hexrays_cfunc_get_lvar(self.ptr, idx, &mut info) };
        if ok { Some(info.into()) } else { None }
    }

    /// Get all local variables
    pub fn lvars(&self) -> Vec<LocalVariable> {
        let count = self.lvar_count();
        (0..count).filter_map(|i| self.get_lvar(i)).collect()
    }

    /// Find a local variable by name, returns its index
    pub fn find_lvar_by_name(&self, name: &str) -> Option<usize> {
        let cname = CString::new(name).ok()?;
        let idx = unsafe { idalib_hexrays_cfunc_find_lvar_by_name(self.ptr, cname.as_ptr()) };
        if idx >= 0 { Some(idx as usize) } else { None }
    }
}

// ============================================================================
// Persistent lvar modification functions (work without a decompiled cfunc)
// ============================================================================

/// Rename a local variable (persistent - saved to IDB)
pub fn rename_lvar(func_ea: Address, oldname: &str, newname: &str) -> bool {
    let coldname = match CString::new(oldname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cnewname = match CString::new(newname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_rename_lvar(func_ea.into(), coldname.as_ptr(), cnewname.as_ptr()) }
}

/// Set local variable type (persistent - saved to IDB)
pub fn set_lvar_type(func_ea: Address, varname: &str, type_str: &str) -> bool {
    let cvarname = match CString::new(varname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let ctype = match CString::new(type_str) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_lvar_type(func_ea.into(), cvarname.as_ptr(), ctype.as_ptr()) }
}

/// Set local variable comment (persistent - saved to IDB)
pub fn set_lvar_comment(func_ea: Address, varname: &str, comment: &str) -> bool {
    let cvarname = match CString::new(varname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let ccmt = match CString::new(comment) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_lvar_cmt(func_ea.into(), cvarname.as_ptr(), ccmt.as_ptr()) }
}

/// Set whether a variable should be treated as non-pointer
pub fn set_lvar_noptr(func_ea: Address, varname: &str, noptr: bool) -> bool {
    let cvarname = match CString::new(varname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_lvar_noptr(func_ea.into(), cvarname.as_ptr(), noptr) }
}

/// Map one variable to another (merge them)
pub fn map_lvar(func_ea: Address, from_name: &str, to_name: &str) -> bool {
    let cfrom = match CString::new(from_name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let cto = match CString::new(to_name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_map_lvar(func_ea.into(), cfrom.as_ptr(), cto.as_ptr()) }
}

/// Unmap a variable (undo a merge)
pub fn unmap_lvar(func_ea: Address, varname: &str) -> bool {
    let cvarname = match CString::new(varname) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_unmap_lvar(func_ea.into(), cvarname.as_ptr()) }
}

// ============================================================================
// User-defined call types (override call site signatures)
// ============================================================================

/// Set a user-defined call type at a specific call site
pub fn set_call_type(func_ea: Address, call_ea: Address, decl: &str) -> bool {
    let cdecl = match CString::new(decl) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_call_type(func_ea.into(), call_ea.into(), cdecl.as_ptr()) }
}

/// Remove a user-defined call type at a specific call site
pub fn del_call_type(func_ea: Address, call_ea: Address) -> bool {
    unsafe { idalib_hexrays_del_call_type(func_ea.into(), call_ea.into()) }
}

/// Get the user-defined call type at a specific call site
pub fn get_call_type(func_ea: Address, call_ea: Address) -> Option<String> {
    let result = unsafe { idalib_hexrays_get_call_type(func_ea.into(), call_ea.into()) };
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ============================================================================
// Function type/signature manipulation
// ============================================================================

/// Get function type/signature as a string
pub fn get_func_type(func_ea: Address) -> Option<String> {
    let result = unsafe { idalib_hexrays_get_func_type(func_ea.into()) };
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Set function type/signature from a C declaration
pub fn set_func_type(func_ea: Address, decl: &str) -> bool {
    let cdecl = match CString::new(decl) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_func_type(func_ea.into(), cdecl.as_ptr()) }
}

/// Get the number of function arguments
pub fn get_func_arg_count(func_ea: Address) -> Option<usize> {
    let count = unsafe { idalib_hexrays_get_func_arg_count(func_ea.into()) };
    if count >= 0 {
        Some(count as usize)
    } else {
        None
    }
}

/// Get function argument info by index
pub fn get_func_arg(func_ea: Address, idx: usize) -> Option<FunctionArgument> {
    let mut info = func_arg_info_t::default();
    let ok = unsafe { idalib_hexrays_get_func_arg(func_ea.into(), idx as i32, &mut info) };
    if ok { Some(info.into()) } else { None }
}

/// Get all function arguments
pub fn get_func_args(func_ea: Address) -> Vec<FunctionArgument> {
    let count = get_func_arg_count(func_ea).unwrap_or(0);
    (0..count)
        .filter_map(|i| get_func_arg(func_ea, i))
        .collect()
}

/// Set function argument name
pub fn set_func_arg_name(func_ea: Address, idx: usize, name: &str) -> bool {
    let cname = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_func_arg_name(func_ea.into(), idx as i32, cname.as_ptr()) }
}

/// Set function argument type
pub fn set_func_arg_type(func_ea: Address, idx: usize, type_str: &str) -> bool {
    let ctype = match CString::new(type_str) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_func_arg_type(func_ea.into(), idx as i32, ctype.as_ptr()) }
}

/// Get function return type
pub fn get_func_rettype(func_ea: Address) -> Option<String> {
    let result = unsafe { idalib_hexrays_get_func_rettype(func_ea.into()) };
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Set function return type
pub fn set_func_rettype(func_ea: Address, type_str: &str) -> bool {
    let ctype = match CString::new(type_str) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_func_rettype(func_ea.into(), ctype.as_ptr()) }
}

/// Get function calling convention
pub fn get_func_cc(func_ea: Address) -> Option<String> {
    let result = unsafe { idalib_hexrays_get_func_cc(func_ea.into()) };
    if result.is_empty() || result == "unknown" {
        None
    } else {
        Some(result)
    }
}

/// Set function calling convention
/// Valid values: "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__pascal", "__usercall"
pub fn set_func_cc(func_ea: Address, cc_name: &str) -> bool {
    let ccc = match CString::new(cc_name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_hexrays_set_func_cc(func_ea.into(), ccc.as_ptr()) }
}

/// Clear cached decompilation result to force re-decompilation
pub fn clear_cached_cfunc(func_ea: Address) {
    unsafe { idalib_hexrays_clear_cached_cfunc(func_ea.into()) }
}

impl<'a> CBlock<'a> {
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
