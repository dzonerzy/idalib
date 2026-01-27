#pragma once

#include "typeinf.hpp"
#include "nalt.hpp"
#include "lines.hpp"

#include "cxx.h"

// Get the type string at an address (e.g., "int", "char *", "struct foo")
// Returns empty string if no type is defined at the address
rust::String idalib_get_type_str(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    qstring out;
    if (tif.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// Get the type of an operand at an address
// Returns empty string if no type is defined for the operand
rust::String idalib_get_op_type_str(ea_t ea, int n) {
  tinfo_t tif;
  if (get_op_tinfo(&tif, ea, n)) {
    qstring out;
    if (tif.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// Print the type at an address using IDA's print_type function
// This gives a more complete representation including the name
rust::String idalib_print_type(ea_t ea, int flags) {
  qstring out;
  if (print_type(&out, ea, flags)) {
    return rust::String(out.c_str());
  }
  return rust::String("");
}

// Check if a type is defined at an address
bool idalib_has_type(ea_t ea) {
  tinfo_t tif;
  return get_tinfo(&tif, ea);
}

// Delete the type at an address
void idalib_del_type(ea_t ea) {
  del_tinfo(ea);
}

// Parse a C declaration and apply it to an address
// decl: C declaration string (e.g., "int foo" or "void __stdcall func(int x)")
// Returns true on success
bool idalib_apply_cdecl(ea_t ea, const char *decl) {
  tinfo_t tif;
  qstring name;
  
  // Parse the declaration
  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    return false;
  }
  
  // Apply the type
  return apply_tinfo(ea, tif, TINFO_DEFINITE);
}

// Parse a C declaration and return the resulting type string
// This is useful for validating type strings
rust::String idalib_parse_decl(const char *decl) {
  tinfo_t tif;
  qstring name;
  
  if (parse_decl(&tif, &name, nullptr, decl, PT_SIL)) {
    qstring out;
    if (tif.print(&out, name.empty() ? nullptr : name.c_str())) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// Get the size of a type at an address (in bytes)
// Returns 0 if no type is defined
uint64_t idalib_get_type_size(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.get_size();
  }
  return 0;
}

// Check if type at address is a pointer
bool idalib_is_ptr_type(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_ptr();
  }
  return false;
}

// Check if type at address is a function
bool idalib_is_func_type(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_func();
  }
  return false;
}

// Check if type at address is a struct/union
bool idalib_is_struct_type(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_struct() || tif.is_union();
  }
  return false;
}

// Check if type at address is an array
bool idalib_is_array_type(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_array();
  }
  return false;
}

// Check if type at address is an enum
bool idalib_is_enum_type(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_enum();
  }
  return false;
}

// Get the function prototype as a string (for function addresses)
rust::String idalib_get_func_prototype(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && tif.is_func()) {
    qstring out;
    // Print with function arguments
    if (tif.print(&out, nullptr, PRTYPE_1LINE)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// ============================================================================
// Named Type Operations
// ============================================================================

// Apply a named type from the type library to an address
// name: name of the type in the type library (e.g., "SOCKET", "HANDLE", "FILE")
// Returns true on success
bool idalib_apply_named_type(ea_t ea, const char *name) {
  return apply_named_type(ea, name);
}

// Get a named type from the type library and return its string representation
// name: name of the type (e.g., "SOCKET", "HANDLE", "size_t")
// Returns empty string if type not found
rust::String idalib_get_named_type(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name)) {
    qstring out;
    if (tif.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// Check if a named type exists in the type library
bool idalib_has_named_type(const char *name) {
  tinfo_t tif;
  return tif.get_named_type(nullptr, name);
}

// Get the size of a named type
uint64_t idalib_get_named_type_size(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name)) {
    return tif.get_size();
  }
  return 0;
}

// Get the TID (type ID) for a named type
// Returns BADADDR if not found
uint64_t idalib_get_named_type_tid(const char *name) {
  return get_named_type_tid(name);
}

// ============================================================================
// Numbered Type Operations (ordinal-based access to local types)
// ============================================================================

// Get the number of local types
uint32_t idalib_get_ordinal_count() {
  return get_ordinal_count(nullptr);
}

// Get a type by its ordinal number
rust::String idalib_get_numbered_type(uint32_t ordinal) {
  tinfo_t tif;
  if (tif.get_numbered_type(nullptr, ordinal)) {
    qstring out;
    if (tif.print(&out)) {
      return rust::String(out.c_str());
    }
  }
  return rust::String("");
}

// Get the name of a numbered type
rust::String idalib_get_numbered_type_name(uint32_t ordinal) {
  const char *name = get_numbered_type_name(nullptr, ordinal);
  if (name != nullptr) {
    return rust::String(name);
  }
  return rust::String("");
}

// ============================================================================
// UDT (Struct/Union) Operations
// ============================================================================

// Get the number of members in a struct/union at an address
int32_t idalib_get_udt_member_count(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return static_cast<int32_t>(udt.size());
    }
  }
  return -1;
}

// Get information about a UDT member by index
// Returns: "name|type|offset|size" or empty string if not found
rust::String idalib_get_udt_member_info(ea_t ea, uint32_t index) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt) && index < udt.size()) {
      const udm_t &member = udt[index];
      qstring type_str;
      member.type.print(&type_str);
      
      qstring result;
      result.sprnt("%s|%s|%llu|%llu",
                   member.name.c_str(),
                   type_str.c_str(),
                   (unsigned long long)(member.offset / 8),  // Convert bits to bytes
                   (unsigned long long)member.size);
      return rust::String(result.c_str());
    }
  }
  return rust::String("");
}

// Get the total size of a UDT at an address
uint64_t idalib_get_udt_size(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return udt.total_size;
    }
  }
  return 0;
}

// Check if UDT at address is a union (vs struct)
bool idalib_is_udt_union(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea)) {
    return tif.is_union();
  }
  return false;
}

// Find a UDT member by name and return its index (-1 if not found)
int32_t idalib_find_udt_member_by_name(ea_t ea, const char *name) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return static_cast<int32_t>(udt.find_member(name));
    }
  }
  return -1;
}

// Find the UDT member at a given byte offset
int32_t idalib_find_udt_member_by_offset(ea_t ea, uint64_t offset) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && (tif.is_struct() || tif.is_union())) {
    // find_udm expects offset in bits
    return tif.find_udm(offset * 8, STRMEM_AUTO);
  }
  return -1;
}

// ============================================================================
// Named UDT Operations (by type name instead of address)
// ============================================================================

// Get the number of members in a named struct/union
int32_t idalib_get_named_udt_member_count(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return static_cast<int32_t>(udt.size());
    }
  }
  return -1;
}

// Get information about a named UDT member by index
rust::String idalib_get_named_udt_member_info(const char *name, uint32_t index) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt) && index < udt.size()) {
      const udm_t &member = udt[index];
      qstring type_str;
      member.type.print(&type_str);
      
      qstring result;
      result.sprnt("%s|%s|%llu|%llu",
                   member.name.c_str(),
                   type_str.c_str(),
                   (unsigned long long)(member.offset / 8),
                   (unsigned long long)member.size);
      return rust::String(result.c_str());
    }
  }
  return rust::String("");
}

// Get the total size of a named UDT
uint64_t idalib_get_named_udt_size(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return udt.total_size;
    }
  }
  return 0;
}

// Check if named type is a union
bool idalib_is_named_udt_union(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name)) {
    return tif.is_union();
  }
  return false;
}

// Find a member by name in a named UDT
int32_t idalib_find_named_udt_member_by_name(const char *udt_name, const char *member_name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, udt_name) && (tif.is_struct() || tif.is_union())) {
    udt_type_data_t udt;
    if (tif.get_udt_details(&udt)) {
      return static_cast<int32_t>(udt.find_member(member_name));
    }
  }
  return -1;
}

// Find member by offset in a named UDT
int32_t idalib_find_named_udt_member_by_offset(const char *name, uint64_t offset) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && (tif.is_struct() || tif.is_union())) {
    return tif.find_udm(offset * 8, STRMEM_AUTO);
  }
  return -1;
}

// ============================================================================
// Enum Operations
// ============================================================================

// Get the number of members in an enum at an address
int32_t idalib_get_enum_member_count(ea_t ea) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && tif.is_enum()) {
    enum_type_data_t etd;
    if (tif.get_enum_details(&etd)) {
      return static_cast<int32_t>(etd.size());
    }
  }
  return -1;
}

// Get enum member info by index
// Returns: "name|value" or empty string if not found
rust::String idalib_get_enum_member_info(ea_t ea, uint32_t index) {
  tinfo_t tif;
  if (get_tinfo(&tif, ea) && tif.is_enum()) {
    enum_type_data_t etd;
    if (tif.get_enum_details(&etd) && index < etd.size()) {
      const edm_t &member = etd[index];
      qstring result;
      result.sprnt("%s|%llu", member.name.c_str(), (unsigned long long)member.value);
      return rust::String(result.c_str());
    }
  }
  return rust::String("");
}

// Get enum member count for a named enum
int32_t idalib_get_named_enum_member_count(const char *name) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && tif.is_enum()) {
    enum_type_data_t etd;
    if (tif.get_enum_details(&etd)) {
      return static_cast<int32_t>(etd.size());
    }
  }
  return -1;
}

// Get named enum member info by index
rust::String idalib_get_named_enum_member_info(const char *name, uint32_t index) {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, name) && tif.is_enum()) {
    enum_type_data_t etd;
    if (tif.get_enum_details(&etd) && index < etd.size()) {
      const edm_t &member = etd[index];
      qstring result;
      result.sprnt("%s|%llu", member.name.c_str(), (unsigned long long)member.value);
      return rust::String(result.c_str());
    }
  }
  return rust::String("");
}

// ============================================================================
// Import Type Library
// ============================================================================

// Import a type library (.til file)
// Returns true on success
bool idalib_import_type_library(const char *tilname) {
  return add_til(tilname, ADDTIL_DEFAULT) != 0;
}

// List loaded type libraries
// Returns semicolon-separated list of loaded til names
rust::String idalib_get_loaded_tils() {
  qstring result;
  til_t *idati = get_idati();
  if (idati == nullptr) {
    return rust::String("");
  }
  int n = idati->nbases;
  for (int i = 0; i < n; i++) {
    til_t *til = idati->base[i];
    if (til != nullptr && til->name != nullptr) {
      if (!result.empty()) {
        result.append(";");
      }
      result.append(til->name);
    }
  }
  return rust::String(result.c_str());
}

// ============================================================================
// UDT Creation and Modification Operations
// ============================================================================

// Create an empty struct/union in the local type library
// name: name of the new struct/union
// is_union: true for union, false for struct
// Returns the ordinal of the new type, or 0 on failure
uint32_t idalib_create_udt(const char *name, bool is_union) {
  // First check if type already exists
  tinfo_t existing;
  if (existing.get_named_type(nullptr, name)) {
    return 0;  // Type already exists
  }
  
  // Create the UDT
  tinfo_t tif;
  if (!tif.create_udt(is_union)) {
    return 0;
  }
  
  // Save it to the local type library with the given name
  tinfo_code_t code = tif.set_named_type(nullptr, name, NTF_TYPE);
  if (code != TERR_OK) {
    return 0;
  }
  
  return tif.get_ordinal();
}

// Add a member to a struct/union by type name
// udt_name: name of the struct/union to modify
// member_name: name of the new member
// member_type: C type declaration for the member (e.g., "int", "char *", "unsigned long")
// offset: bit offset where to place the member (use -1 for auto-placement at end)
// Returns tinfo_code_t value (TERR_OK = 0 on success)
int32_t idalib_add_udt_member(const char *udt_name, const char *member_name, const char *member_type, int64_t offset) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, udt_name)) {
    return TERR_BAD_TYPE;
  }
  
  if (!tif.is_struct() && !tif.is_union()) {
    return TERR_BAD_TYPE;
  }
  
  // Parse the member type
  tinfo_t mtif;
  qstring mname;
  if (!parse_decl(&mtif, &mname, nullptr, member_type, PT_SIL)) {
    // Try just as a type without name
    qstring decl_with_name;
    decl_with_name.sprnt("%s %s", member_type, member_name);
    if (!parse_decl(&mtif, &mname, nullptr, decl_with_name.c_str(), PT_SIL)) {
      return TERR_BAD_TYPE;
    }
  }
  
  // Calculate offset in bits
  uint64_t bit_offset = 0;
  if (offset < 0) {
    // Auto-place at end: get current unpadded size
    bit_offset = tif.get_unpadded_size() * 8;
  } else {
    bit_offset = static_cast<uint64_t>(offset) * 8;
  }
  
  // Add the member
  tinfo_code_t code = tif.add_udm(member_name, mtif, bit_offset);
  return static_cast<int32_t>(code);
}

// Delete a member from a struct/union by index
// udt_name: name of the struct/union to modify
// member_index: index of the member to delete
// Returns tinfo_code_t value (TERR_OK = 0 on success)
int32_t idalib_del_udt_member(const char *udt_name, uint32_t member_index) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, udt_name)) {
    return TERR_BAD_TYPE;
  }
  
  if (!tif.is_struct() && !tif.is_union()) {
    return TERR_BAD_TYPE;
  }
  
  tinfo_code_t code = tif.del_udm(member_index);
  return static_cast<int32_t>(code);
}

// Delete multiple members from a struct/union by index range
// udt_name: name of the struct/union to modify
// start_index: first member to delete (inclusive)
// end_index: last member to delete (exclusive)
// Returns tinfo_code_t value (TERR_OK = 0 on success)
int32_t idalib_del_udt_members(const char *udt_name, uint32_t start_index, uint32_t end_index) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, udt_name)) {
    return TERR_BAD_TYPE;
  }
  
  if (!tif.is_struct() && !tif.is_union()) {
    return TERR_BAD_TYPE;
  }
  
  tinfo_code_t code = tif.del_udms(start_index, end_index);
  return static_cast<int32_t>(code);
}

// ============================================================================
// Struct Field XRefs
// ============================================================================

// Get the TID (type ID) for a struct/union member
// This TID can be used to find xrefs to the member
// udt_name: name of the struct/union
// member_index: index of the member
// Returns the TID, or BADADDR if not found
uint64_t idalib_get_udt_member_tid(const char *udt_name, uint32_t member_index) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, udt_name)) {
    return BADADDR;
  }
  
  if (!tif.is_struct() && !tif.is_union()) {
    return BADADDR;
  }
  
  return tif.get_udm_tid(member_index);
}

// Get xrefs to a struct/union member
// udt_name: name of the struct/union
// member_index: index of the member
// Returns semicolon-separated list of addresses that reference this member
rust::String idalib_get_udt_member_xrefs(const char *udt_name, uint32_t member_index) {
  tinfo_t tif;
  if (!tif.get_named_type(nullptr, udt_name)) {
    return rust::String("");
  }
  
  if (!tif.is_struct() && !tif.is_union()) {
    return rust::String("");
  }
  
  tid_t tid = tif.get_udm_tid(member_index);
  if (tid == BADADDR) {
    return rust::String("");
  }
  
  qstring result;
  xrefblk_t xb;
  // XREF_TID tells xrefblk to treat the address as a type ID
  for (bool ok = xb.first_to(tid, XREF_DATA); ok; ok = xb.next_to()) {
    if (!result.empty()) {
      result.append(";");
    }
    result.cat_sprnt("0x%llx", (unsigned long long)xb.from);
  }
  
  return rust::String(result.c_str());
}

// Get xrefs to a named type (struct/union/enum)
// type_name: name of the type
// Returns semicolon-separated list of addresses that reference this type
rust::String idalib_get_type_xrefs(const char *type_name) {
  tid_t tid = get_named_type_tid(type_name);
  if (tid == BADADDR) {
    return rust::String("");
  }
  
  qstring result;
  xrefblk_t xb;
  for (bool ok = xb.first_to(tid, XREF_DATA); ok; ok = xb.next_to()) {
    if (!result.empty()) {
      result.append(";");
    }
    result.cat_sprnt("0x%llx", (unsigned long long)xb.from);
  }
  
  return rust::String(result.c_str());
}
