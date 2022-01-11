/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ARCH_X64_H
#define ARCH_X64_H

#include "format_rtl.h"
#include "format_asm.h"
using namespace std;

class x64 {
  private:
    format_rtl rtlTool;
    format_asm asmTool;
    STR_STR myAsmRtl;
    fstream inpFile, outFile;
    /* X64 Instruction Tools */
    void rectify_label(string& asm_ins, string& rtl);
    void rectify_symbol(string& asm_ins, string& rtl);
    void rectify_reg(string& rtl);
  public:
    /* Functions for X64 */
    STR_STR read_all(const char *fileName);
    /* Initialization */
    void auto_setup();
    /* Utilities */
    void print_list(const char *fileName, STR_STR& myAsmRtl);
};

#endif