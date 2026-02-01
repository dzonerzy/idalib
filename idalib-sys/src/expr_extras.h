#pragma once

#include "pro.h"
#include "expr.hpp"

#include "cxx.h"

// Check if Python extlang is available
inline bool idalib_has_python_extlang() {
    const extlang_object_t el = find_extlang_by_ext("py");
    return el != nullptr && el->eval_snippet != nullptr;
}

// Evaluate a Python code snippet
// Returns true on success, false on failure (error message stored in out_error)
inline bool idalib_eval_python_snippet(rust::Str code, rust::String &out_error) {
    out_error = rust::String();

    const extlang_object_t el = find_extlang_by_ext("py");
    if (el == nullptr) {
        out_error = rust::String("Python extlang not found");
        return false;
    }

    if (el->eval_snippet == nullptr) {
        out_error = rust::String("Python eval_snippet not available");
        return false;
    }

    qstring errbuf;
    std::string code_str(code.data(), code.length());

    bool success = el->eval_snippet(code_str.c_str(), &errbuf);

    if (!success && !errbuf.empty()) {
        out_error = rust::String(errbuf.c_str());
    }

    return success;
}

// Evaluate an IDC expression
// Returns true on success, false on failure (error message stored in out_error)
inline bool idalib_eval_idc_expr(rust::Str expr, rust::String &out_error) {
    out_error = rust::String();

    qstring errbuf;
    idc_value_t rv;
    std::string expr_str(expr.data(), expr.length());

    bool success = eval_idc_expr(&rv, BADADDR, expr_str.c_str(), &errbuf);

    if (!success && !errbuf.empty()) {
        out_error = rust::String(errbuf.c_str());
    }

    return success;
}

// Get the name of the current extlang (if any)
inline rust::String idalib_get_current_extlang_name() {
    const extlang_object_t el = get_extlang();
    if (el != nullptr && el->name != nullptr) {
        return rust::String(el->name);
    }
    return rust::String();
}
