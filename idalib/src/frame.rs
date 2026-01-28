//! Stack frame analysis and manipulation
//!
//! This module provides functions for working with function stack frames,
//! including local variables, arguments, and saved registers.

use std::ffi::CString;

use crate::Address;
use crate::ffi::frame::{
    idalib_define_stkvar, idalib_delete_frame_members, idalib_find_frame_member_by_name,
    idalib_find_frame_member_by_offset, idalib_get_effective_spd, idalib_get_frame_args_size,
    idalib_get_frame_fpd, idalib_get_frame_lvars_size, idalib_get_frame_member,
    idalib_get_frame_member_count, idalib_get_frame_regs_size, idalib_get_frame_retsize,
    idalib_get_frame_size, idalib_get_spd, idalib_has_frame, idalib_set_frame_member_type,
};

/// Information about a stack frame member (local variable or argument)
#[derive(Debug, Clone)]
pub struct FrameMember {
    /// Member name
    pub name: String,
    /// Offset from frame base (in bytes)
    pub offset: u64,
    /// Size of the member (in bytes)
    pub size: u64,
    /// Type of the member as a string
    pub type_str: String,
}

impl FrameMember {
    /// Parse frame member info from semicolon-separated string
    fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(';').collect();
        if parts.len() < 4 {
            return None;
        }
        Some(FrameMember {
            name: parts[0].to_string(),
            offset: parts[1].parse().ok()?,
            size: parts[2].parse().ok()?,
            type_str: parts[3].to_string(),
        })
    }
}

/// Information about a function's stack frame
#[derive(Debug, Clone)]
pub struct FrameInfo {
    /// Total frame size (local vars + saved regs + args)
    pub total_size: u64,
    /// Size of local variables section
    pub local_vars_size: u64,
    /// Size of saved registers section
    pub saved_regs_size: u64,
    /// Size of arguments section
    pub args_size: u64,
    /// Frame pointer delta
    pub fpd: i64,
    /// Return address size
    pub ret_size: i32,
    /// Number of frame members
    pub member_count: u32,
}

/// Get the total size of a function's stack frame
pub fn get_frame_size(func_addr: Address) -> u64 {
    unsafe { idalib_get_frame_size(func_addr.into()) }
}

/// Get the size of the local variables section
pub fn get_local_vars_size(func_addr: Address) -> u64 {
    unsafe { idalib_get_frame_lvars_size(func_addr.into()) }
}

/// Get the size of the saved registers section
pub fn get_saved_regs_size(func_addr: Address) -> u64 {
    unsafe { idalib_get_frame_regs_size(func_addr.into()) }
}

/// Get the size of the arguments section
pub fn get_args_size(func_addr: Address) -> u64 {
    unsafe { idalib_get_frame_args_size(func_addr.into()) }
}

/// Get the frame pointer delta
pub fn get_fpd(func_addr: Address) -> i64 {
    unsafe { idalib_get_frame_fpd(func_addr.into()) }
}

/// Get the return address size
pub fn get_ret_size(func_addr: Address) -> i32 {
    unsafe { idalib_get_frame_retsize(func_addr.into()) }
}

/// Check if a function has a stack frame
pub fn has_frame(func_addr: Address) -> bool {
    unsafe { idalib_has_frame(func_addr.into()) }
}

/// Get complete frame information for a function
pub fn get_frame_info(func_addr: Address) -> Option<FrameInfo> {
    if !has_frame(func_addr) {
        return None;
    }

    Some(FrameInfo {
        total_size: get_frame_size(func_addr),
        local_vars_size: get_local_vars_size(func_addr),
        saved_regs_size: get_saved_regs_size(func_addr),
        args_size: get_args_size(func_addr),
        fpd: get_fpd(func_addr),
        ret_size: get_ret_size(func_addr),
        member_count: get_frame_member_count(func_addr),
    })
}

/// Get the number of frame members (stack variables)
pub fn get_frame_member_count(func_addr: Address) -> u32 {
    unsafe { idalib_get_frame_member_count(func_addr.into()) }
}

/// Get a frame member by index
pub fn get_frame_member(func_addr: Address, index: u32) -> Option<FrameMember> {
    let result = unsafe { idalib_get_frame_member(func_addr.into(), index) };
    if result.is_empty() {
        return None;
    }
    FrameMember::from_string(&result)
}

/// Get all frame members for a function
pub fn get_frame_members(func_addr: Address) -> Vec<FrameMember> {
    let count = get_frame_member_count(func_addr);
    let mut members = Vec::with_capacity(count as usize);
    for i in 0..count {
        if let Some(member) = get_frame_member(func_addr, i) {
            members.push(member);
        }
    }
    members
}

/// Find a frame member by its offset from the frame base
pub fn find_frame_member_by_offset(func_addr: Address, offset: u64) -> Option<FrameMember> {
    let result = unsafe { idalib_find_frame_member_by_offset(func_addr.into(), offset) };
    if result.is_empty() {
        return None;
    }
    FrameMember::from_string(&result)
}

/// Find a frame member by name
pub fn find_frame_member_by_name(func_addr: Address, name: &str) -> Option<FrameMember> {
    let c_name = CString::new(name).ok()?;
    let result = unsafe { idalib_find_frame_member_by_name(func_addr.into(), c_name.as_ptr()) };
    if result.is_empty() {
        return None;
    }
    FrameMember::from_string(&result)
}

/// Define a stack variable
///
/// # Arguments
/// * `func_addr` - Address of the function
/// * `name` - Name for the stack variable
/// * `stkoff` - Stack offset (relative to SP)
/// * `type_str` - Optional type string (C declaration like "int" or "char*")
pub fn define_stkvar(func_addr: Address, name: &str, stkoff: i64, type_str: Option<&str>) -> bool {
    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let c_type = match type_str {
        Some(t) => match CString::new(t) {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => CString::new("").unwrap(),
    };
    unsafe { idalib_define_stkvar(func_addr.into(), c_name.as_ptr(), stkoff, c_type.as_ptr()) }
}

/// Delete frame members in a range
///
/// # Arguments
/// * `func_addr` - Address of the function
/// * `start_offset` - Start offset of range to delete
/// * `end_offset` - End offset of range to delete
pub fn delete_frame_members(func_addr: Address, start_offset: u64, end_offset: u64) -> bool {
    unsafe { idalib_delete_frame_members(func_addr.into(), start_offset, end_offset) }
}

/// Set the type of a frame member at the given offset
///
/// # Arguments
/// * `func_addr` - Address of the function
/// * `offset` - Offset of the member in the frame
/// * `type_str` - Type string (C declaration like "int" or "struct foo")
pub fn set_frame_member_type(func_addr: Address, offset: u64, type_str: &str) -> bool {
    let c_type = match CString::new(type_str) {
        Ok(s) => s,
        Err(_) => return false,
    };
    unsafe { idalib_set_frame_member_type(func_addr.into(), offset, c_type.as_ptr()) }
}

/// Get the SP delta at a specific address
///
/// Returns the difference between the initial and current values of SP
pub fn get_spd(func_addr: Address, ea: Address) -> i64 {
    unsafe { idalib_get_spd(func_addr.into(), ea.into()) }
}

/// Get the effective SP delta at a specific address
///
/// Takes into account the frame pointer delta
pub fn get_effective_spd(func_addr: Address, ea: Address) -> i64 {
    unsafe { idalib_get_effective_spd(func_addr.into(), ea.into()) }
}
