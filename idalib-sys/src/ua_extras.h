#pragma once

#include "ua.hpp"
#include "lines.hpp"

#include "cxx.h"

// Get instruction mnemonic as a string (with color codes stripped)
rust::String idalib_print_insn_mnem(ea_t ea) {
  qstring out;
  if (print_insn_mnem(&out, ea)) {
    // Strip color codes
    qstring clean;
    tag_remove(&clean, out);
    return rust::String(clean.c_str());
  }
  return rust::String("");
}

// Get operand as a string (with color codes stripped)
// n is the operand index (0-based)
rust::String idalib_print_operand(ea_t ea, int n) {
  qstring out;
  if (print_operand(&out, ea, n, 0, nullptr)) {
    // Strip color codes
    qstring clean;
    tag_remove(&clean, out);
    return rust::String(clean.c_str());
  }
  return rust::String("");
}
