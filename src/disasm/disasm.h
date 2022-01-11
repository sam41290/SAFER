#ifndef _DISASM_H
#define _DISASM_H

#include "Instruction.h"
#include <stdio.h>
#include <stdint.h>
#include <capstone/capstone.h>

using namespace std;
using namespace SBI;
#define OBJDUMP disassembleObj
#define CAPSTONE disassembleCaps

#define DISASENGN CAPSTONE

#define INVALIDINS(str,bytes,loc,ind,size,inslst) \
  if(str.find("(bad)") != string::npos) {\
    LOG("Objdump Gap found at: " <<hex<< loc);\
    handle_gaps(bytes, loc, ind, size,inslst);\
    continue;\
  }


#define DISASSEMBLE(bytes, size, start, ins_list) \
	DISASENGN(bytes, size, start, ins_list)

class DisasmEngn {
  string bname_;
  //csh handle_;
  unordered_map <uint64_t, Instruction *> insCache_;
  //unordered_map <uint64_t, vector <Instruction *>> insSeq_;
  vector <uint64_t> sectionEnds_;
public:
  DisasmEngn(string bname, vector <uint64_t> sec_ends) {
    bname_ = bname;
    sectionEnds_ = sec_ends;
    std::sort(sectionEnds_.begin(),sectionEnds_.end());
  }
  void disassembleCaps (uint8_t bytes[], int size, uint64_t start,
  		       vector <Instruction *> &ins_list);
  void disassembleObj (uint8_t bytes[], int size, uint64_t start,
  		      vector <Instruction *> &ins_list);
  
  vector <Instruction *> readIns(uint64_t start, uint64_t end);
  vector <Instruction *> getIns(uint64_t start, int ins_cnt);
  void createInsCache(uint64_t code_start, uint64_t code_end);
};
#endif
