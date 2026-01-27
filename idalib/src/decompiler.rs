use std::marker::PhantomData;

use crate::Address;
use crate::ffi::hexrays::{
    cblock_iter, cblock_t, cfunc_t, cfuncptr_t, cinsn_t, idalib_hexrays_cblock_iter,
    idalib_hexrays_cblock_iter_next, idalib_hexrays_cblock_len, idalib_hexrays_cfunc_pseudocode,
    idalib_hexrays_cfuncptr_inner, idalib_hexrays_cinsn_ea, idalib_hexrays_cinsn_is_expr,
    idalib_hexrays_cinsn_label_num, idalib_hexrays_cinsn_op, idalib_hexrays_cinsn_opname,
};
use crate::idb::IDB;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

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
