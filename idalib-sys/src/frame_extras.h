#pragma once

#include "frame.hpp"
#include "funcs.hpp"
#include "typeinf.hpp"

#include "cxx.h"

// Get the full size of a function frame
// Returns: frame size or 0 if no frame
uint64_t idalib_get_frame_size(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_frame_size(pfn);
}

// Get local variables size
uint64_t idalib_get_frame_lvars_size(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return pfn->frsize;
}

// Get saved registers size
uint64_t idalib_get_frame_regs_size(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return pfn->frregs;
}

// Get arguments size
uint64_t idalib_get_frame_args_size(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return pfn->argsize;
}

// Get frame pointer delta
int64_t idalib_get_frame_fpd(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return pfn->fpd;
}

// Get return address size
int32_t idalib_get_frame_retsize(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return get_frame_retsize(pfn);
}

// Check if function has a frame
bool idalib_has_frame(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return get_frame_size(pfn) > 0;
}

// Get number of frame members (stack variables)
uint32_t idalib_get_frame_member_count(ea_t func_ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  
  tinfo_t frame_type;
  if (!get_func_frame(&frame_type, pfn)) {
    return 0;
  }
  
  udt_type_data_t udt;
  if (!frame_type.get_udt_details(&udt)) {
    return 0;
  }
  
  return (uint32_t)udt.size();
}

// Get frame member info by index
// Returns semicolon-separated: name;offset;size;type_string
rust::String idalib_get_frame_member(ea_t func_ea, uint32_t index) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String("");
  }
  
  tinfo_t frame_type;
  if (!get_func_frame(&frame_type, pfn)) {
    return rust::String("");
  }
  
  udt_type_data_t udt;
  if (!frame_type.get_udt_details(&udt)) {
    return rust::String("");
  }
  
  if (index >= udt.size()) {
    return rust::String("");
  }
  
  const udm_t &member = udt[index];
  
  qstring name = member.name;
  
  qstring type_str;
  member.type.print(&type_str);
  
  // Format: name;offset;size;type_string
  qstring result;
  result.sprnt("%s;%llu;%llu;%s", 
               name.c_str(),
               (uint64_t)member.offset / 8,  // Convert bits to bytes
               (uint64_t)member.size / 8,    // Convert bits to bytes
               type_str.c_str());
  
  return rust::String(result.c_str());
}

// Find frame member by offset (in bytes, relative to frame base)
// Returns semicolon-separated: name;offset;size;type_string or empty if not found
rust::String idalib_find_frame_member_by_offset(ea_t func_ea, uint64_t offset) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String("");
  }
  
  tinfo_t frame_type;
  if (!get_func_frame(&frame_type, pfn)) {
    return rust::String("");
  }
  
  udt_type_data_t udt;
  if (!frame_type.get_udt_details(&udt)) {
    return rust::String("");
  }
  
  // Convert offset to bits for comparison
  uint64_t offset_bits = offset * 8;
  
  for (size_t i = 0; i < udt.size(); i++) {
    const udm_t &member = udt[i];
    if (member.offset == offset_bits) {
      qstring name = member.name;
      
      qstring type_str;
      member.type.print(&type_str);
      
      qstring result;
      result.sprnt("%s;%llu;%llu;%s", 
                   name.c_str(),
                   (uint64_t)member.offset / 8,
                   (uint64_t)member.size / 8,
                   type_str.c_str());
      
      return rust::String(result.c_str());
    }
  }
  
  return rust::String("");
}

// Find frame member by name
// Returns semicolon-separated: name;offset;size;type_string or empty if not found
rust::String idalib_find_frame_member_by_name(ea_t func_ea, const char *name) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return rust::String("");
  }
  
  tinfo_t frame_type;
  if (!get_func_frame(&frame_type, pfn)) {
    return rust::String("");
  }
  
  udt_type_data_t udt;
  if (!frame_type.get_udt_details(&udt)) {
    return rust::String("");
  }
  
  int idx = udt.find_member(name);
  if (idx < 0) {
    return rust::String("");
  }
  
  const udm_t &member = udt[idx];
  
  qstring member_name = member.name;
  
  qstring type_str;
  member.type.print(&type_str);
  
  qstring result;
  result.sprnt("%s;%llu;%llu;%s", 
               member_name.c_str(),
               (uint64_t)member.offset / 8,
               (uint64_t)member.size / 8,
               type_str.c_str());
  
  return rust::String(result.c_str());
}

// Define a stack variable
bool idalib_define_stkvar(ea_t func_ea, const char *name, int64_t stkoff, const char *type_str) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  
  tinfo_t tif;
  if (type_str != nullptr && type_str[0] != '\0') {
    if (!tif.deserialize(nullptr, (const uchar**)&type_str, nullptr)) {
      // Try parsing as C declaration
      qstring parse_type = type_str;
      parse_type.append(";");
      if (!parse_decl(&tif, nullptr, nullptr, parse_type.c_str(), PT_SIL)) {
        return false;
      }
    }
  } else {
    // Default to int type
    tif.create_simple_type(BT_INT);
  }
  
  return define_stkvar(pfn, name, stkoff, tif, nullptr);
}

// Delete frame members in a range
bool idalib_delete_frame_members(ea_t func_ea, uint64_t start_offset, uint64_t end_offset) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  
  return delete_frame_members(pfn, start_offset, end_offset);
}

// Set the type of a frame member at given offset
bool idalib_set_frame_member_type(ea_t func_ea, uint64_t offset, const char *type_str) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return false;
  }
  
  tinfo_t tif;
  if (type_str != nullptr && type_str[0] != '\0') {
    // Try parsing as C declaration
    qstring parse_type = type_str;
    parse_type.append(";");
    if (!parse_decl(&tif, nullptr, nullptr, parse_type.c_str(), PT_SIL)) {
      return false;
    }
  } else {
    return false;
  }
  
  return set_frame_member_type(pfn, offset, tif, nullptr, 0);
}

// Get SP delta at a specific address
int64_t idalib_get_spd(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  
  return get_spd(pfn, ea);
}

// Get effective SP delta at a specific address
int64_t idalib_get_effective_spd(ea_t func_ea, ea_t ea) {
  func_t *pfn = get_func(func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  
  return get_effective_spd(pfn, ea);
}
