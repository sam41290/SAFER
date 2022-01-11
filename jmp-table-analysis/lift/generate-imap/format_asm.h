/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FORMAT_ASM_H
#define FORMAT_ASM_H

#include "custom_type.h"
using namespace std;

class format_asm {
  private:
    /* ASM Tools */
    void clear_space(string& asm_ins);
  public:
    /* Functions for ASM */
    bool is_valid_asm(const string& asm_ins);
    bool is_asm_directive(const string& asm_ins);
    void clean_up(string& asm_ins);
    bool has_label(const string& asm_ins, const size_t& asmPos);
    string get_next_word(const string& asm_ins);
    void standard_format(string& asm_ins);
};

#endif