#pragma once

#include "pro.h"
#include "funcs.hpp"
#include "gdl.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

uint64_t idalib_func_flags(const func_t *f) {
  return f == nullptr ? 0 : f->flags;
}

rust::String idalib_func_name(const func_t *f) {
  auto name = qstring();

  if (get_func_name(&name, f->start_ea) != 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

rust::String idalib_get_func_cmt(const func_t *f, bool rptble) {
  auto cmt = qstring();

  if (get_func_cmt(&cmt, f, rptble) != 0) {
    return rust::String(cmt.c_str());
  } else {
    return rust::String();
  }
}

bool idalib_set_func_cmt(const func_t *f, const char *cmt, bool rptble) {
  return set_func_cmt(f, cmt, rptble);
}

std::unique_ptr<qflow_chart_t> idalib_func_flow_chart(func_t *f, int fc_options) {
  if (auto cfg = std::make_unique<qflow_chart_t>(nullptr, f, BADADDR, BADADDR, fc_options); cfg != nullptr) {
    return cfg;
  }
  throw std::runtime_error("cannot build function flow chart");
}

const qbasic_block_t *idalib_qflow_graph_getn_block(const qflow_chart_t *cfg, size_t n) {
  return n < std::size(cfg->blocks) ? &cfg->blocks[n] : nullptr;
}

rust::Slice<const int> idalib_qbasic_block_succs(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->succ), std::size(blk->succ));
}

rust::Slice<const int> idalib_qbasic_block_preds(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->pred), std::size(blk->pred));
}

// Update function in the database after modifying func_t fields
bool idalib_update_func(uint64_t func_ea) {
  func_t *pfn = get_func((ea_t)func_ea);
  if (pfn == nullptr) {
    return false;
  }
  return update_func(pfn);
}

// Set function start address
// Returns: 0=ok, 1=no code at newstart, 2=bad start, 3=no function, 4=refused
int32_t idalib_set_func_start(uint64_t func_ea, uint64_t new_start) {
  return set_func_start((ea_t)func_ea, (ea_t)new_start);
}

// Set function end address
bool idalib_set_func_end(uint64_t func_ea, uint64_t new_end) {
  return set_func_end((ea_t)func_ea, (ea_t)new_end);
}

// Get function flags
uint64_t idalib_get_func_flags(uint64_t func_ea) {
  func_t *pfn = get_func((ea_t)func_ea);
  if (pfn == nullptr) {
    return 0;
  }
  return pfn->flags;
}

// Set function flags
bool idalib_set_func_flags(uint64_t func_ea, uint64_t flags) {
  func_t *pfn = get_func((ea_t)func_ea);
  if (pfn == nullptr) {
    return false;
  }
  pfn->flags = (uint32)flags;
  return update_func(pfn);
}
