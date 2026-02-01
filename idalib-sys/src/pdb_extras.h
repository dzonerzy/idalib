#pragma once

#include "loader.hpp"
#include "netnode.hpp"

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

  // Create/get the PDB netnode
  netnode pdb_node(PDB_NODE_NAME, 0, true);
  if (pdb_node == BADNODE) {
    return false;
  }

  // Set the load address (altval at index 0)
  pdb_node.altset(PDB_DLLBASE_NODE_IDX, load_addr);

  // Set the PDB file path (supstr at index 0)
  size_t path_len = strlen(pdb_path);
  pdb_node.supset(PDB_DLLNAME_NODE_IDX, pdb_path, path_len + 1);

  // Run the PDB plugin with PDB_CC_USER_WITH_DATA
  bool result = run_plugin(pdb_plugin, PDB_CC_USER_WITH_DATA);

  // Check the result stored in the netnode
  // After invocation, result (boolean) is stored in: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
  // Note: We also return the direct result from run_plugin for now
  
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
