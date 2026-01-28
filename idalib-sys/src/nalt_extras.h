#pragma once

#include "nalt.hpp"
#include "pro.h"

#include "cxx.h"

#include <vector>

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    return rust::String(path, size);
  } else {
    return rust::String();
  }
}

// Get the number of import modules (DLLs/libraries)
uint32_t idalib_get_import_module_qty() {
  return get_import_module_qty();
}

// Get the name of an import module by index
rust::String idalib_get_import_module_name(uint32_t mod_index) {
  qstring name;
  if (get_import_module_name(&name, mod_index)) {
    return rust::String(name.c_str());
  }
  return rust::String("");
}

// Structure to hold import info for callback
struct ImportCollector {
  std::vector<uint64_t> addresses;
  std::vector<std::string> names;
  std::vector<uint64_t> ordinals;
};

// Callback for enum_import_names
static int idaapi import_enum_callback(ea_t ea, const char *name, uval_t ord, void *param) {
  ImportCollector *collector = (ImportCollector *)param;
  collector->addresses.push_back(ea);
  collector->names.push_back(name ? name : "");
  collector->ordinals.push_back(ord);
  return 1; // Continue enumeration
}

// Get number of imports in a module
uint32_t idalib_get_import_count(uint32_t mod_index) {
  ImportCollector collector;
  enum_import_names(mod_index, import_enum_callback, &collector);
  return (uint32_t)collector.addresses.size();
}

// Get import info by module index and import index
// Returns semicolon-separated: address;name;ordinal
rust::String idalib_get_import(uint32_t mod_index, uint32_t import_index) {
  ImportCollector collector;
  enum_import_names(mod_index, import_enum_callback, &collector);
  
  if (import_index >= collector.addresses.size()) {
    return rust::String("");
  }
  
  qstring result;
  result.sprnt("%llu;%s;%llu",
               (uint64_t)collector.addresses[import_index],
               collector.names[import_index].c_str(),
               (uint64_t)collector.ordinals[import_index]);
  
  return rust::String(result.c_str());
}

// Get all imports from a module as semicolon-separated entries, one per line
// Format per line: address;name;ordinal
rust::String idalib_get_module_imports(uint32_t mod_index) {
  ImportCollector collector;
  enum_import_names(mod_index, import_enum_callback, &collector);
  
  qstring result;
  for (size_t i = 0; i < collector.addresses.size(); i++) {
    if (i > 0) {
      result.append("\n");
    }
    qstring line;
    line.sprnt("%llu;%s;%llu",
               (uint64_t)collector.addresses[i],
               collector.names[i].c_str(),
               (uint64_t)collector.ordinals[i]);
    result.append(line);
  }
  
  return rust::String(result.c_str());
}
