#pragma once

#include "loader.hpp"
#include "netnode.hpp"
#include "segment.hpp"
#include "ida.hpp"
#include "nalt.hpp"

#include <cstdint>
#include <string>

#include "cxx.h"

// PDB node constants (from pdb.hpp)
#define PDB_NODE_NAME             "$ pdb"
#define PDB_DLLBASE_NODE_IDX       0
#define PDB_DLLNAME_NODE_IDX       0

// PDB call codes
enum pdb_callcode_t {
  PDB_CC_USER = 0,
  PDB_CC_IDA  = 1,
  PDB_CC_USER_WITH_DATA = 3,
  PDB_CC_IDA_COFF = 4,
};

// Load PDB file for the currently open database
// pdb_path: path to the PDB file
// load_addr: base address where the module is loaded (use 0 for the default image base)
// Returns: true if PDB was loaded successfully, false otherwise
inline bool idalib_load_pdb(const char* pdb_path, uint64_t load_addr) {
  if (pdb_path == nullptr || pdb_path[0] == '\0') {
    return false;
  }

  // Find the PDB plugin
  const plugin_t* pdb_plugin = find_plugin("pdb", true);
  if (pdb_plugin == nullptr) {
    return false;
  }

  // If load_addr is 0, get the image base from IDA's inf structure
  // get_imagebase() is the actual PE image base address
  if (load_addr == 0) {
    load_addr = (uint64_t)get_imagebase();
  }

  // Create the PDB netnode exactly as IDA does it
  netnode pdb_node;
  pdb_node.create(PDB_NODE_NAME);

  // Set the load address (altval at index 0)
  pdb_node.altset(PDB_DLLBASE_NODE_IDX, load_addr);

  // Set the PDB file path (supset at index 0)
  // The plugin reads this back with supstr()
  size_t path_len = strlen(pdb_path);
  pdb_node.supset(PDB_DLLNAME_NODE_IDX, pdb_path, path_len + 1);

  // Run the PDB plugin with PDB_CC_USER_WITH_DATA
  // PDB_CC_USER_WITH_DATA = load additional pdb with data from netnode
  bool result = run_plugin(pdb_plugin, PDB_CC_USER_WITH_DATA);
  
  return result;
}

// Get the result of the last PDB load operation
// Returns the value stored in the PDB netnode after loading
inline uint64_t idalib_get_pdb_load_result() {
  netnode pdb_node(PDB_NODE_NAME);
  if (pdb_node == BADNODE) {
    return 0;
  }
  return pdb_node.altval(PDB_DLLBASE_NODE_IDX);
}

// Get the current image base for debugging
inline uint64_t idalib_get_current_imagebase() {
  return (uint64_t)get_imagebase();
}

// Get recent IDA messages (for debugging)
inline void idalib_get_messages(char* out_buf, size_t buf_size, int count) {
  if (out_buf == nullptr || buf_size == 0) return;
  out_buf[0] = '\0';
  
  qstrvec_t lines;
  msg_get_lines(&lines, count);
  
  size_t pos = 0;
  for (size_t i = 0; i < lines.size() && pos < buf_size - 1; i++) {
    size_t len = lines[i].length();
    if (pos + len + 1 >= buf_size) break;
    qstrncpy(out_buf + pos, lines[i].c_str(), buf_size - pos);
    pos += len;
    if (pos < buf_size - 1) {
      out_buf[pos++] = '\n';
    }
  }
  out_buf[pos] = '\0';
}

// Debug function to verify netnode state before/after PDB load
inline bool idalib_verify_pdb_netnode(uint64_t* out_load_addr, char* out_path, size_t path_size) {
  netnode pdb_node(PDB_NODE_NAME);
  if (pdb_node == BADNODE) {
    return false;
  }
  
  if (out_load_addr) {
    *out_load_addr = pdb_node.altval(PDB_DLLBASE_NODE_IDX);
  }
  
  if (out_path && path_size > 0) {
    qstring tmp;
    pdb_node.supstr(&tmp, PDB_DLLNAME_NODE_IDX);
    // Use qstrncpy instead of strncpy (IDA SDK safe function)
    qstrncpy(out_path, tmp.c_str(), path_size);
  }
  
  return true;
}
