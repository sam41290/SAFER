/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include <cctype>
#include "format_asm.h"
using namespace std;

/* ------------------------- ASM Tools ------------------------- */
void format_asm::clear_space(string& asm_ins) {
  // replace double space by single space
  size_t pos = asm_ins.find("  ");
  while (pos != string::npos) {
    asm_ins.erase(pos, 1);
    pos = asm_ins.find("  ");
  }
}

/* --------------------- Functions for ASM --------------------- */
bool format_asm::is_valid_asm(const string& asm_ins) {
  // simply check if 1st character is a-z
  size_t pos = asm_ins.find_first_not_of(" \t");
  if (pos != string::npos && isalpha(asm_ins[pos]))
    return true;
  return false;
}

bool format_asm::is_asm_directive(const string& asm_ins) {
  // directive asm begins with '.'
  size_t pos = asm_ins.find_first_not_of(" \t");
  if (pos != string::npos && asm_ins[pos] == '.')
    return true;
  return false;
}

void format_asm::clean_up(string& asm_ins) {
  // remove comment: #...
  size_t pos = asm_ins.find('#');
  if (pos != string::npos)
    asm_ins.erase(pos, string::npos);
  // clear space
  clear_space(asm_ins);
}

bool format_asm::has_label(const string& asm_ins, const size_t& asmPos) {
  // check if current asm, indicated by asmPos, has label
  // note that there could be a few consecutive asms in asm_ins
  size_t label_loc = asm_ins.find(".L", asmPos);
  size_t semicolon_loc = asm_ins.find(";", asmPos);
  return (label_loc != string::npos && label_loc < semicolon_loc);
}

string format_asm::get_next_word(const string& asm_ins) {
  // ignore tab, space and semicolon to get next word
  size_t i = asm_ins.find_first_not_of("; \t");
  size_t j = asm_ins.find_first_of("; \t", i);
  if (i == string::npos || j == string::npos)
    return "NO_NEXT_WORD";
  return asm_ins.substr(i, j-i);
}

void format_asm::standard_format(string& asm_ins) {
  // remove tab before semicolon
  size_t pos = asm_ins.find("\t;");
  while (pos != string::npos) {
    asm_ins.erase(pos, 1);
    pos = asm_ins.find("\t;");
  }
}