use std::marker::PhantomData;

use crate::ffi::BADADDR;
use crate::ffi::bytes::idalib_get_bytes;
use crate::ffi::strings::{
    build_strlist, clear_strlist, get_strlist_qty, idalib_get_string_layout,
    idalib_get_string_width, idalib_get_strlist_item_addr, idalib_get_strlist_item_length,
    idalib_get_strlist_item_type,
};

use crate::Address;
use crate::idb::IDB;

pub type StringIndex = usize;

/// String character width
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringWidth {
    /// 1 byte characters (ASCII/UTF-8)
    Byte1,
    /// 2 byte characters (UTF-16)
    Byte2,
    /// 4 byte characters (UTF-32)
    Byte4,
    /// Unknown width
    Unknown(i32),
}

impl From<i32> for StringWidth {
    fn from(value: i32) -> Self {
        match value {
            0 => StringWidth::Byte1,
            1 => StringWidth::Byte2,
            2 => StringWidth::Byte4,
            v => StringWidth::Unknown(v),
        }
    }
}

/// String layout/encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringLayout {
    /// Null-terminated (C-style)
    NullTerminated,
    /// Pascal-style with 1-byte length prefix
    Pascal1,
    /// Pascal-style with 2-byte length prefix
    Pascal2,
    /// Pascal-style with 4-byte length prefix
    Pascal4,
    /// Unknown layout
    Unknown(i32),
}

impl From<i32> for StringLayout {
    fn from(value: i32) -> Self {
        match value {
            0 => StringLayout::NullTerminated,
            1 => StringLayout::Pascal1,
            2 => StringLayout::Pascal2,
            3 => StringLayout::Pascal4,
            v => StringLayout::Unknown(v),
        }
    }
}

/// Complete string type information
#[derive(Debug, Clone, Copy)]
pub struct StringType {
    /// Raw type value from IDA
    pub raw: i32,
    /// Character width
    pub width: StringWidth,
    /// String layout
    pub layout: StringLayout,
}

impl StringType {
    /// Get a human-readable string type name
    pub fn name(&self) -> &'static str {
        match (self.width, self.layout) {
            (StringWidth::Byte1, StringLayout::NullTerminated) => "c",
            (StringWidth::Byte2, StringLayout::NullTerminated) => "c_16",
            (StringWidth::Byte4, StringLayout::NullTerminated) => "c_32",
            (StringWidth::Byte1, StringLayout::Pascal1) => "pascal",
            (StringWidth::Byte2, StringLayout::Pascal1) => "pascal_16",
            (StringWidth::Byte4, StringLayout::Pascal1) => "pascal_32",
            (StringWidth::Byte1, StringLayout::Pascal2) => "len2",
            (StringWidth::Byte2, StringLayout::Pascal2) => "len2_16",
            (StringWidth::Byte4, StringLayout::Pascal2) => "len2_32",
            (StringWidth::Byte1, StringLayout::Pascal4) => "len4",
            (StringWidth::Byte2, StringLayout::Pascal4) => "len4_16",
            (StringWidth::Byte4, StringLayout::Pascal4) => "len4_32",
            _ => "unknown",
        }
    }

    /// Check if this is a wide string (2 or 4 byte characters)
    pub fn is_wide(&self) -> bool {
        matches!(self.width, StringWidth::Byte2 | StringWidth::Byte4)
    }
}

pub struct StringList<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> StringList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn rebuild(&self) {
        unsafe { build_strlist() }
    }

    pub fn clear(&self) {
        unsafe { clear_strlist() }
    }

    pub fn get_by_index(&self, index: StringIndex) -> Option<String> {
        let addr = self.get_address_by_index(index)?;
        let size = self.get_length_by_index(index);

        // See also `IDB::get_bytes`
        let mut buf = Vec::with_capacity(size);
        let Ok(new_len) = (unsafe { idalib_get_bytes(addr.into(), &mut buf) }) else {
            return None;
        };
        unsafe {
            buf.set_len(new_len);
        }

        // TODO: switch to `String::from_utf8_lossy_owned` once it's stable
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    pub fn get_address_by_index(&self, index: StringIndex) -> Option<Address> {
        let addr = unsafe { idalib_get_strlist_item_addr(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    fn get_length_by_index(&self, index: StringIndex) -> usize {
        unsafe { idalib_get_strlist_item_length(index) }
    }

    /// Get the string type for a string at the given index
    pub fn get_type_by_index(&self, index: StringIndex) -> StringType {
        let raw = unsafe { idalib_get_strlist_item_type(index) };
        let width = unsafe { idalib_get_string_width(raw) };
        let layout = unsafe { idalib_get_string_layout(raw) };
        StringType {
            raw,
            width: StringWidth::from(width),
            layout: StringLayout::from(layout),
        }
    }

    pub fn len(&self) -> usize {
        unsafe { get_strlist_qty() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> StringListIter<'_, 'a> {
        StringListIter {
            string_list: self,
            current_index: 0,
        }
    }
}

pub struct StringListIter<'s, 'a> {
    string_list: &'s StringList<'a>,
    current_index: StringIndex,
}

impl<'s, 'a> Iterator for StringListIter<'s, 'a> {
    type Item = (Address, String);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.string_list.len() {
            let addr = self.string_list.get_address_by_index(self.current_index);
            let string = self.string_list.get_by_index(self.current_index);

            self.current_index += 1;

            if let (Some(addr), Some(string)) = (addr, string) {
                return Some((addr, string));
            };
            // skip invalid strings, such as:
            // - the index became invalid, such as if a string was undefined
            // - the string failed to decode (today: not UTF-8)
        }
        None
    }
}
