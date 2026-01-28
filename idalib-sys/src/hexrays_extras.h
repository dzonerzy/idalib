#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_func(f, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

// cinsn_t accessors
// Get the statement type (ctype_t value as int)
int idalib_hexrays_cinsn_op(const cinsn_t *insn) {
  return static_cast<int>(insn->op);
}

// Get the address associated with the statement
uint64_t idalib_hexrays_cinsn_ea(const cinsn_t *insn) {
  return insn->ea;
}

// Get the label number (-1 means no label)
int idalib_hexrays_cinsn_label_num(const cinsn_t *insn) {
  return insn->label_num;
}

// Check if this is an expression (cot_* types)
bool idalib_hexrays_cinsn_is_expr(const cinsn_t *insn) {
  return insn->is_expr();
}

// Get the statement type as a string
rust::String idalib_hexrays_cinsn_opname(const cinsn_t *insn) {
  switch (insn->op) {
    // Expression types (cot_*)
    case cot_empty:    return rust::String("empty_expr");
    case cot_comma:    return rust::String("comma");        // x, y
    case cot_asg:      return rust::String("assign");       // x = y
    case cot_asgbor:   return rust::String("assign_or");    // x |= y
    case cot_asgxor:   return rust::String("assign_xor");   // x ^= y
    case cot_asgband:  return rust::String("assign_and");   // x &= y
    case cot_asgadd:   return rust::String("assign_add");   // x += y
    case cot_asgsub:   return rust::String("assign_sub");   // x -= y
    case cot_asgmul:   return rust::String("assign_mul");   // x *= y
    case cot_asgsshr:  return rust::String("assign_sshr");  // x >>= y signed
    case cot_asgushr:  return rust::String("assign_ushr");  // x >>= y unsigned
    case cot_asgshl:   return rust::String("assign_shl");   // x <<= y
    case cot_asgsdiv:  return rust::String("assign_sdiv");  // x /= y signed
    case cot_asgudiv:  return rust::String("assign_udiv");  // x /= y unsigned
    case cot_asgsmod:  return rust::String("assign_smod");  // x %= y signed
    case cot_asgumod:  return rust::String("assign_umod");  // x %= y unsigned
    case cot_tern:     return rust::String("ternary");      // x ? y : z
    case cot_lor:      return rust::String("lor");          // x || y
    case cot_land:     return rust::String("land");         // x && y
    case cot_bor:      return rust::String("bor");          // x | y
    case cot_xor:      return rust::String("xor");          // x ^ y
    case cot_band:     return rust::String("band");         // x & y
    case cot_eq:       return rust::String("eq");           // x == y
    case cot_ne:       return rust::String("ne");           // x != y
    case cot_sge:      return rust::String("sge");          // x >= y signed
    case cot_uge:      return rust::String("uge");          // x >= y unsigned
    case cot_sle:      return rust::String("sle");          // x <= y signed
    case cot_ule:      return rust::String("ule");          // x <= y unsigned
    case cot_sgt:      return rust::String("sgt");          // x > y signed
    case cot_ugt:      return rust::String("ugt");          // x > y unsigned
    case cot_slt:      return rust::String("slt");          // x < y signed
    case cot_ult:      return rust::String("ult");          // x < y unsigned
    case cot_sshr:     return rust::String("sshr");         // x >> y signed
    case cot_ushr:     return rust::String("ushr");         // x >> y unsigned
    case cot_shl:      return rust::String("shl");          // x << y
    case cot_add:      return rust::String("add");          // x + y
    case cot_sub:      return rust::String("sub");          // x - y
    case cot_mul:      return rust::String("mul");          // x * y
    case cot_sdiv:     return rust::String("sdiv");         // x / y signed
    case cot_udiv:     return rust::String("udiv");         // x / y unsigned
    case cot_smod:     return rust::String("smod");         // x % y signed
    case cot_umod:     return rust::String("umod");         // x % y unsigned
    case cot_fadd:     return rust::String("fadd");         // x + y fp
    case cot_fsub:     return rust::String("fsub");         // x - y fp
    case cot_fmul:     return rust::String("fmul");         // x * y fp
    case cot_fdiv:     return rust::String("fdiv");         // x / y fp
    case cot_fneg:     return rust::String("fneg");         // -x fp
    case cot_neg:      return rust::String("neg");          // -x
    case cot_cast:     return rust::String("cast");         // (type)x
    case cot_lnot:     return rust::String("lnot");         // !x
    case cot_bnot:     return rust::String("bnot");         // ~x
    case cot_ptr:      return rust::String("ptr");          // *x
    case cot_ref:      return rust::String("ref");          // &x
    case cot_postinc:  return rust::String("postinc");      // x++
    case cot_postdec:  return rust::String("postdec");      // x--
    case cot_preinc:   return rust::String("preinc");       // ++x
    case cot_predec:   return rust::String("predec");       // --x
    case cot_call:     return rust::String("call");         // x(...)
    case cot_idx:      return rust::String("idx");          // x[y]
    case cot_memref:   return rust::String("memref");       // x.m
    case cot_memptr:   return rust::String("memptr");       // x->m
    case cot_num:      return rust::String("num");          // number
    case cot_fnum:     return rust::String("fnum");         // floating point number
    case cot_str:      return rust::String("str");          // string constant
    case cot_obj:      return rust::String("obj");          // obj_ea
    case cot_var:      return rust::String("var");          // variable
    case cot_insn:     return rust::String("insn");         // instruction in expression
    case cot_sizeof:   return rust::String("sizeof");       // sizeof(x)
    case cot_helper:   return rust::String("helper");       // arbitrary name
    case cot_type:     return rust::String("type");         // arbitrary type
    // Statement types (cit_*)
    case cit_empty:    return rust::String("empty");
    case cit_block:    return rust::String("block");        // { ... }
    case cit_expr:     return rust::String("expr");         // expr;
    case cit_if:       return rust::String("if");           // if-statement
    case cit_for:      return rust::String("for");          // for-statement
    case cit_while:    return rust::String("while");        // while-statement
    case cit_do:       return rust::String("do");           // do-statement
    case cit_switch:   return rust::String("switch");       // switch-statement
    case cit_break:    return rust::String("break");        // break
    case cit_continue: return rust::String("continue");     // continue
    case cit_return:   return rust::String("return");       // return
    case cit_goto:     return rust::String("goto");         // goto
    case cit_asm:      return rust::String("asm");          // asm-statement
    case cit_try:      return rust::String("try");          // try-statement
    case cit_throw:    return rust::String("throw");        // throw-statement
    default:           return rust::String("unknown");
  }
}

// ============================================================================
// Local Variable (lvar) Support
// ============================================================================

#ifndef CXXBRIDGE1_STRUCT_lvar_info_t
#define CXXBRIDGE1_STRUCT_lvar_info_t
struct lvar_info_t final {
  ::std::int32_t idx;           // Index in lvars_t
  ::rust::String name;          // Variable name
  ::rust::String type_str;      // Type as string
  ::std::int32_t width;         // Size in bytes
  ::std::uint64_t defea;        // Definition address
  ::std::int32_t defblk;        // Definition block
  bool is_arg;                  // Is a function argument
  bool is_stk_var;              // Is on the stack
  bool is_reg_var;              // Is in a register
  bool has_user_name;           // Has user-defined name
  bool has_user_type;           // Has user-defined type
  ::rust::String cmt;           // Variable comment

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_lvar_info_t

// Get the number of local variables in a decompiled function
size_t idalib_hexrays_cfunc_lvar_count(cfunc_t *f) {
  if (f == nullptr || f->mba == nullptr) return 0;
  return f->mba->vars.size();
}

// Get info about a local variable by index
bool idalib_hexrays_cfunc_get_lvar(cfunc_t *f, size_t idx, lvar_info_t *out) {
  if (f == nullptr || f->mba == nullptr) return false;
  if (idx >= f->mba->vars.size()) return false;

  const lvar_t &v = f->mba->vars[idx];
  out->idx = static_cast<int32_t>(idx);
  out->name = rust::String(v.name.c_str());

  qstring type_buf;
  if (v.type().print(&type_buf)) {
    out->type_str = rust::String(type_buf.c_str());
  } else {
    out->type_str = rust::String("");
  }

  out->width = v.width;
  out->defea = v.defea;
  out->defblk = v.defblk;
  out->is_arg = v.is_arg_var();
  out->is_stk_var = v.is_stk_var();
  out->is_reg_var = v.is_reg_var();
  out->has_user_name = v.has_user_name();
  out->has_user_type = v.has_user_type();
  out->cmt = rust::String(v.cmt.c_str());

  return true;
}

// Get lvar by name
int32_t idalib_hexrays_cfunc_find_lvar_by_name(cfunc_t *f, const char *name) {
  if (f == nullptr || f->mba == nullptr) return -1;
  for (size_t i = 0; i < f->mba->vars.size(); i++) {
    if (f->mba->vars[i].name == name) {
      return static_cast<int32_t>(i);
    }
  }
  return -1;
}

// Rename a local variable (persistent)
bool idalib_hexrays_rename_lvar(uint64_t func_ea, const char *oldname, const char *newname) {
  return rename_lvar(static_cast<ea_t>(func_ea), oldname, newname);
}

// Set local variable type (persistent)
bool idalib_hexrays_set_lvar_type(uint64_t func_ea, const char *varname, const char *type_str) {
  lvar_saved_info_t info;
  if (!locate_lvar(&info.ll, static_cast<ea_t>(func_ea), varname)) {
    return false;
  }

  tinfo_t tif;
  qstring name;
  if (!parse_decl(&tif, &name, nullptr, type_str, PT_SIL)) {
    return false;
  }

  info.type = tif;
  return modify_user_lvar_info(static_cast<ea_t>(func_ea), MLI_TYPE, info);
}

// Set local variable comment (persistent)
bool idalib_hexrays_set_lvar_cmt(uint64_t func_ea, const char *varname, const char *cmt) {
  lvar_saved_info_t info;
  if (!locate_lvar(&info.ll, static_cast<ea_t>(func_ea), varname)) {
    return false;
  }

  info.cmt = cmt;
  return modify_user_lvar_info(static_cast<ea_t>(func_ea), MLI_CMT, info);
}

// Set noptr flag for a variable
bool idalib_hexrays_set_lvar_noptr(uint64_t func_ea, const char *varname, bool noptr) {
  lvar_saved_info_t info;
  if (!locate_lvar(&info.ll, static_cast<ea_t>(func_ea), varname)) {
    return false;
  }

  if (noptr) {
    info.flags = LVINF_NOPTR;
    return modify_user_lvar_info(static_cast<ea_t>(func_ea), MLI_SET_FLAGS, info);
  } else {
    info.flags = LVINF_NOPTR;
    return modify_user_lvar_info(static_cast<ea_t>(func_ea), MLI_CLR_FLAGS, info);
  }
}

// Map one variable to another (merge)
bool idalib_hexrays_map_lvar(uint64_t func_ea, const char *from_name, const char *to_name) {
  lvar_uservec_t lvinf;
  if (!restore_user_lvar_settings(&lvinf, static_cast<ea_t>(func_ea))) {
    // No existing settings, create new
  }

  lvar_locator_t from_ll, to_ll;
  if (!locate_lvar(&from_ll, static_cast<ea_t>(func_ea), from_name)) {
    return false;
  }
  if (!locate_lvar(&to_ll, static_cast<ea_t>(func_ea), to_name)) {
    return false;
  }

  lvinf.lmaps[from_ll] = to_ll;
  save_user_lvar_settings(static_cast<ea_t>(func_ea), lvinf);
  return true;
}

// Unmap a variable
bool idalib_hexrays_unmap_lvar(uint64_t func_ea, const char *varname) {
  lvar_uservec_t lvinf;
  if (!restore_user_lvar_settings(&lvinf, static_cast<ea_t>(func_ea))) {
    return false;
  }

  lvar_locator_t ll;
  if (!locate_lvar(&ll, static_cast<ea_t>(func_ea), varname)) {
    return false;
  }

  // Find and remove from mapping
  auto it = lvinf.lmaps.find(ll);
  if (it != lvinf.lmaps.end()) {
    lvinf.lmaps.erase(it);
    save_user_lvar_settings(static_cast<ea_t>(func_ea), lvinf);
    return true;
  }
  return false;
}

// ============================================================================
// User-Defined Calls (override call site signatures)
// ============================================================================

// Set a user-defined call type at a specific address
bool idalib_hexrays_set_call_type(uint64_t func_ea, uint64_t call_ea, const char *decl) {
  udcall_t udc;
  
  // Ensure declaration ends with semicolon (required by parse_decl)
  qstring decl_str(decl);
  if (!decl_str.empty() && decl_str.last() != ';') {
    decl_str.append(';');
  }
  
  // Try parse_user_call first
  if (!parse_user_call(&udc, decl_str.c_str(), true)) {
    // Try alternative: manually parse the declaration
    tinfo_t tif;
    qstring name;
    if (!parse_decl(&tif, &name, nullptr, decl_str.c_str(), PT_SIL)) {
      return false;
    }
    udc.tif = tif;
    udc.name = name;
  }

  udcall_map_t udcalls;
  restore_user_defined_calls(&udcalls, static_cast<ea_t>(func_ea));

  udcalls[static_cast<ea_t>(call_ea)] = udc;
  save_user_defined_calls(static_cast<ea_t>(func_ea), udcalls);
  return true;
}

// Remove a user-defined call type at a specific address
bool idalib_hexrays_del_call_type(uint64_t func_ea, uint64_t call_ea) {
  udcall_map_t udcalls;
  if (!restore_user_defined_calls(&udcalls, static_cast<ea_t>(func_ea))) {
    return false;
  }

  auto it = udcalls.find(static_cast<ea_t>(call_ea));
  if (it != udcalls.end()) {
    udcalls.erase(it);
    save_user_defined_calls(static_cast<ea_t>(func_ea), udcalls);
    return true;
  }
  return false;
}

// Get user-defined call type at a specific address
rust::String idalib_hexrays_get_call_type(uint64_t func_ea, uint64_t call_ea) {
  udcall_map_t udcalls;
  if (!restore_user_defined_calls(&udcalls, static_cast<ea_t>(func_ea))) {
    return rust::String("");
  }

  auto it = udcalls.find(static_cast<ea_t>(call_ea));
  if (it != udcalls.end()) {
    qstring buf;
    if (it->second.tif.print(&buf)) {
      std::stringstream ss;
      ss << it->second.name.c_str() << " " << buf.c_str();
      return rust::String(ss.str());
    }
  }
  return rust::String("");
}

// ============================================================================
// Function Type/Signature Manipulation
// ============================================================================

// Get function prototype/signature as string
rust::String idalib_hexrays_get_func_type(uint64_t func_ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return rust::String("");
  }

  qstring buf;
  if (tif.print(&buf)) {
    return rust::String(buf.c_str());
  }
  return rust::String("");
}

// Set function type/signature
bool idalib_hexrays_set_func_type(uint64_t func_ea, const char *decl) {
  tinfo_t tif;
  qstring name;
  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return false;
  }

  return apply_tinfo(static_cast<ea_t>(func_ea), tif, TINFO_DEFINITE);
}

// Get function argument count
int32_t idalib_hexrays_get_func_arg_count(uint64_t func_ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return -1;
  }

  if (!tif.is_func()) {
    return -1;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return -1;
  }

  return static_cast<int32_t>(ftd.size());
}

#ifndef CXXBRIDGE1_STRUCT_func_arg_info_t
#define CXXBRIDGE1_STRUCT_func_arg_info_t
struct func_arg_info_t final {
  ::std::int32_t idx;           // Argument index
  ::rust::String name;          // Argument name
  ::rust::String type_str;      // Type as string

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_func_arg_info_t

// Get function argument info by index
bool idalib_hexrays_get_func_arg(uint64_t func_ea, int32_t idx, func_arg_info_t *out) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return false;
  }

  if (!tif.is_func()) {
    return false;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return false;
  }

  if (idx < 0 || static_cast<size_t>(idx) >= ftd.size()) {
    return false;
  }

  const funcarg_t &arg = ftd[idx];
  out->idx = idx;
  out->name = rust::String(arg.name.c_str());

  qstring type_buf;
  if (arg.type.print(&type_buf)) {
    out->type_str = rust::String(type_buf.c_str());
  } else {
    out->type_str = rust::String("");
  }

  return true;
}

// Set function argument name
bool idalib_hexrays_set_func_arg_name(uint64_t func_ea, int32_t idx, const char *name) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return false;
  }

  if (!tif.is_func()) {
    return false;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return false;
  }

  if (idx < 0 || static_cast<size_t>(idx) >= ftd.size()) {
    return false;
  }

  ftd[idx].name = name;

  tinfo_t new_tif;
  if (!new_tif.create_func(ftd)) {
    return false;
  }

  return apply_tinfo(static_cast<ea_t>(func_ea), new_tif, TINFO_DEFINITE);
}

// Set function argument type
bool idalib_hexrays_set_func_arg_type(uint64_t func_ea, int32_t idx, const char *type_str) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return false;
  }

  if (!tif.is_func()) {
    return false;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return false;
  }

  if (idx < 0 || static_cast<size_t>(idx) >= ftd.size()) {
    return false;
  }

  tinfo_t arg_type;
  qstring arg_name;
  if (!parse_decl(&arg_type, &arg_name, nullptr, type_str, PT_SIL)) {
    return false;
  }

  ftd[idx].type = arg_type;

  tinfo_t new_tif;
  if (!new_tif.create_func(ftd)) {
    return false;
  }

  return apply_tinfo(static_cast<ea_t>(func_ea), new_tif, TINFO_DEFINITE);
}

// Get function return type
rust::String idalib_hexrays_get_func_rettype(uint64_t func_ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return rust::String("");
  }

  if (!tif.is_func()) {
    return rust::String("");
  }

  tinfo_t rettype = tif.get_rettype();
  qstring buf;
  if (rettype.print(&buf)) {
    return rust::String(buf.c_str());
  }
  return rust::String("");
}

// Set function return type
bool idalib_hexrays_set_func_rettype(uint64_t func_ea, const char *type_str) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return false;
  }

  if (!tif.is_func()) {
    return false;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return false;
  }

  tinfo_t rettype;
  qstring ret_name;
  if (!parse_decl(&rettype, &ret_name, nullptr, type_str, PT_SIL)) {
    return false;
  }

  ftd.rettype = rettype;

  tinfo_t new_tif;
  if (!new_tif.create_func(ftd)) {
    return false;
  }

  return apply_tinfo(static_cast<ea_t>(func_ea), new_tif, TINFO_DEFINITE);
}

// Get function calling convention
rust::String idalib_hexrays_get_func_cc(uint64_t func_ea) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return rust::String("");
  }

  if (!tif.is_func()) {
    return rust::String("");
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return rust::String("");
  }

  callcnv_t cc = ftd.get_cc();
  switch (cc & CM_CC_MASK) {
    case CM_CC_CDECL:    return rust::String("__cdecl");
    case CM_CC_STDCALL:  return rust::String("__stdcall");
    case CM_CC_FASTCALL: return rust::String("__fastcall");
    case CM_CC_THISCALL: return rust::String("__thiscall");
    case CM_CC_PASCAL:   return rust::String("__pascal");
    case CM_CC_SPECIAL:  return rust::String("__usercall");
    case CM_CC_SPOILED:  return rust::String("__spoiled");
    default:             return rust::String("unknown");
  }
}

// Set function calling convention
bool idalib_hexrays_set_func_cc(uint64_t func_ea, const char *cc_name) {
  tinfo_t tif;
  if (!get_tinfo(&tif, static_cast<ea_t>(func_ea))) {
    return false;
  }

  if (!tif.is_func()) {
    return false;
  }

  func_type_data_t ftd;
  if (!tif.get_func_details(&ftd)) {
    return false;
  }

  callcnv_t new_cc = CM_CC_UNKNOWN;
  if (strcmp(cc_name, "__cdecl") == 0 || strcmp(cc_name, "cdecl") == 0) {
    new_cc = CM_CC_CDECL;
  } else if (strcmp(cc_name, "__stdcall") == 0 || strcmp(cc_name, "stdcall") == 0) {
    new_cc = CM_CC_STDCALL;
  } else if (strcmp(cc_name, "__fastcall") == 0 || strcmp(cc_name, "fastcall") == 0) {
    new_cc = CM_CC_FASTCALL;
  } else if (strcmp(cc_name, "__thiscall") == 0 || strcmp(cc_name, "thiscall") == 0) {
    new_cc = CM_CC_THISCALL;
  } else if (strcmp(cc_name, "__pascal") == 0 || strcmp(cc_name, "pascal") == 0) {
    new_cc = CM_CC_PASCAL;
  } else if (strcmp(cc_name, "__usercall") == 0 || strcmp(cc_name, "usercall") == 0) {
    new_cc = CM_CC_SPECIAL;
  } else {
    return false;
  }

  ftd.set_cc(new_cc);

  tinfo_t new_tif;
  if (!new_tif.create_func(ftd)) {
    return false;
  }

  return apply_tinfo(static_cast<ea_t>(func_ea), new_tif, TINFO_DEFINITE);
}

// Force re-decompilation by clearing cached info
void idalib_hexrays_clear_cached_cfunc(uint64_t func_ea) {
  mark_cfunc_dirty(static_cast<ea_t>(func_ea));
}
