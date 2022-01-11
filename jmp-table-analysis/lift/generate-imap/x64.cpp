/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "x64.h"
using namespace std;

/* ------------------- X64 Instruction Tools ------------------- */
/* pass label from asm into rtl */
void x64::rectify_label(string& asm_ins, string& rtl) {
  size_t tPos, pos = 0, asmPos = 0;
  string op, label;
  bool use_label_ref;
  // x86 :: remove redundant string (e.g. "@gotoff") in asm
  size_t t1, t2;
  if (rtl.find("label_ref:") != string::npos) {
    t1 = asm_ins.find('@');
    while (t1 != string::npos) {
      t2 = asm_ins.find_first_of("(;, \t", t1+1);
      asm_ins.erase(t1, t2-t1);
      t1 = asm_ins.find('@', t1);
    }
  }
  // find "label_ref" in rtl
  pos = rtl.find("label_ref", pos+1);
  while (pos != string::npos) {
    // get op from next asm
    op = asmTool.get_next_word(asm_ins.substr(asmPos, string::npos));
    // if exist, retrieve the label
    // if not, keep using the previous label
    if (op.compare("NO_NEXT_WORD") != 0) {
      // if op is not a jump, search for next jump
      // remove "op.compare("NO_NEXT_WORD") != 0" to find missing jumpList opcode
      while (!asmTool.has_label(asm_ins, asmPos) && op.compare("NO_NEXT_WORD") != 0) {
        asmPos = asm_ins.find(';', asmPos);
        if (asmPos == string::npos)
          return;
        op = asmTool.get_next_word(asm_ins.substr(asmPos, string::npos));
      }
      if (op.compare("NO_NEXT_WORD") != 0) {
        // get the label
        asmPos = asm_ins.find(op, asmPos) + op.length();
        label = asmTool.get_next_word(asm_ins.substr(asmPos, string::npos));
        label = label.substr(0,label.find_first_of("(;,"));
        label = label.substr(label.find_first_not_of("$"), string::npos);
        asmPos = asm_ins.find(';', asmPos);
      }
      else
        // if no corresponding label in asm, just reduce it to "(label_ref)"
        label.clear();
    }
    // use_label_ref == false: .L0403
    // use_label_ref == true : *.L0403
    if (rtl.substr(pos-5, 3).compare("use") == 0)
      use_label_ref = true;
    else
      use_label_ref = false;
    // paste into rtl
    pos = rtl.find(' ', pos+9);
    tPos = rtl.find(')', pos);
    if (!use_label_ref && label[0] == '*')
      rtl.replace(pos+1, tPos-(pos+1), label.substr(1, string::npos));
    else
      rtl.replace(pos+1, tPos-(pos+1), label);
    pos = rtl.find("label_ref", pos+1);
  }
}

/* remove redundant string (e.g. "@plt") in asm, quote marks in rtl */
void x64::rectify_symbol(string& asm_ins, string& rtl) {
  size_t t1, t2;
  if (rtl.find("symbol_ref:") != string::npos) {
    t1 = asm_ins.find('@');
    while (t1 != string::npos) {
      t2 = asm_ins.find_first_of("(;, \t", t1+1);
      asm_ins.erase(t1, t2-t1);
      t1 = asm_ins.find('@', t1);
    }

    t1 = rtl.find("symbol_ref:");
    while (t1 != string::npos) {
      t2 = rtl.find("(\"", t1);
      rtl.erase(t2+1, 1);
      t2 = rtl.find("\")", t1);
      rtl.erase(t2, 1);
      t1 = rtl.find("symbol_ref:", t1+1);
    }
  }
}

/* convert register name in RTL based on mode: reg:DI ax => rax */
void x64::rectify_reg(string& rtl) {
  string regName[] =
          { " ax", " bx", " cx", " dx", " si", " di", " bp", " sp",
            " r8", " r9", " r10", " r11", " r12", " r13", " r14", " r15" };
  size_t pos, regLen;
  string mode;
  for (int i = 0; i < 8; ++i) {
    pos = rtl.find(regName[i]);
    regLen = regName[i].length() - 1;
    while (pos != string::npos) {
      ++pos;
      mode = rtl.substr(pos-3, 2);
      if (mode.compare("DI") == 0)
        rtl.insert(pos, "r");
      else if (mode.compare("SI") == 0)
        rtl.insert(pos, "e");
      else if (mode.compare("QI") == 0) {
        if (i < 4) rtl.replace(pos+1, 1, "l");
        else rtl.insert(pos+regLen, "l");
      }
      pos = rtl.find(regName[i], pos+regLen);
    }
  }
  for (int i = 8; i < 16; ++i) {
    pos = rtl.find(regName[i]);
    regLen = regName[i].length() - 1;
    while (pos != string::npos) {
      ++pos;
      mode = rtl.substr(pos-3, 2);
      if (mode.compare("SI") == 0)
        rtl.insert(pos+regLen, "d");
      else if (mode.compare("HI") == 0)
        rtl.insert(pos+regLen, "w");
      else if (mode.compare("QI") == 0)
        rtl.insert(pos+regLen, "b");
      pos = rtl.find(regName[i], pos+regLen);
    }
  }
}

/* --------------------- Functions for X64 --------------------- */
STR_STR x64::read_all(const char *fileName) {
  char stop_reading_asm;
  inpFile.open(fileName, fstream::in);

  string str;
  string rtl = "";
  string asm_ins = "";
  myAsmRtl.clear();

  do {
    // str is rtl :: begin with '#'
    if (str[0] == '#') {
      // if asm_ins not empty, then
      // -- <asm_ins, rtl> is a complete pair
      // -- str starts a new pair
      if (asm_ins.compare("") != 0) {
        // consider only if rtl starts with a keyword
        if (rtlTool.is_line_keyword(rtl)) {
          // format rtl and asm
          rtlTool.clean_up(rtl);
          rectify_label(asm_ins, rtl);
          rectify_symbol(asm_ins, rtl);
          // standardize rtl and asm
          rtlTool.standard_format(rtl);
          asmTool.standard_format(asm_ins);
          // add <asm,rtl> to myAsmRtl
          myAsmRtl.push_back(make_pair(asm_ins, rtl));
        }
        // reset asm_ins and rtl anyway because str starts a new pair
        asm_ins = "";
        rtl = "";
      }
      // if asm_ins is empty and str is new rtl
      // it implies that previous rtl have no corresponding asm_ins
      // simply ignore previous rtl
      else if (rtlTool.is_line_keyword(str.substr(1, str.length()-1)))
        rtl = "";
      // clear '#' and update current rtl
      str.erase(0, 1);
      rtl += str;
      stop_reading_asm = 0;
    }
    // str is asm :: must begin with '\t' and is not a directive asm.
    else if (!stop_reading_asm && asmTool.is_valid_asm(str) && str[0] == '\t') {
      asmTool.clean_up(str);
      asm_ins += str;
      asm_ins += ';';
    }
    else if (asmTool.is_asm_directive(str))
      stop_reading_asm = 1;
  }
  while (getline(inpFile, str));

  // process the last pair <asm_ins, rtl>
  if (rtlTool.is_line_keyword(rtl)) {
    rtlTool.clean_up(rtl);
    rectify_label(asm_ins, rtl);
    rectify_symbol(asm_ins, rtl);
    rtlTool.standard_format(rtl);
    asmTool.standard_format(asm_ins);
    myAsmRtl.push_back(make_pair(asm_ins, rtl));
  }

  inpFile.close();
  return myAsmRtl;
}

/* ----------------------- Initialization ---------------------- */
void x64::auto_setup() {
  rtlTool.auto_setup();
}

/* ------------------------- Utilities ------------------------- */
void x64::print_list(const char *fileName, STR_STR& myAsmRtl) {
  outFile.open(fileName, fstream::out | fstream::app);
  for (STR_STR::iterator i = myAsmRtl.begin(); i != myAsmRtl.end(); ++i) {
    outFile << i->first << endl;
    outFile << i->second << endl;
  }
  outFile.close();
}