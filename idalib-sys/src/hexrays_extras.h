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
