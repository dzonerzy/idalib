#pragma once

#include "strlist.hpp"
#include "nalt.hpp"

#include "cxx.h"

ea_t idalib_get_strlist_item_addr(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.ea;
}

size_t idalib_get_strlist_item_length(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return (size_t)si.length;
}

int32_t idalib_get_strlist_item_type(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.type;
}

// String width constants
// STRWIDTH_1B = 0 (1 byte chars - ASCII)
// STRWIDTH_2B = 1 (2 byte chars - UTF-16)  
// STRWIDTH_4B = 2 (4 byte chars - UTF-32)
// STRWIDTH_MASK = 0x03

// String layout constants (shifted by STRLYT_SHIFT = 2)
// STRLYT_TERMCHR = 0 (null-terminated)
// STRLYT_PASCAL1 = 1 (1-byte length prefix)
// STRLYT_PASCAL2 = 2 (2-byte length prefix)
// STRLYT_PASCAL4 = 3 (4-byte length prefix)

int32_t idalib_get_string_width(int32_t strtype) {
  return strtype & STRWIDTH_MASK;
}

int32_t idalib_get_string_layout(int32_t strtype) {
  return (strtype & STRLYT_MASK) >> STRLYT_SHIFT;
}
