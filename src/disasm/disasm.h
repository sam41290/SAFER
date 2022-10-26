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
  if(str.find("(bad)") != string::npos || \
     str.find(".") != string::npos) {\
    LOG("Objdump invalid ins found at: " <<hex<< loc<<": "<<str);\
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
  unordered_set <uint64_t> gaps_;
  unordered_set <uint64_t> badLoc_;
  unordered_map <uint64_t, pair<uint64_t, uint8_t *>> byteCache_;
public:
  DisasmEngn(string bname, vector <uint64_t> sec_ends) {
    bname_ = bname;
    sectionEnds_ = sec_ends;
    std::sort(sectionEnds_.begin(),sectionEnds_.end());
  }
  void disassembleCaps (uint8_t *bytes, int size, uint64_t start,
  		       vector <Instruction *> &ins_list);
  void disassembleObj (uint8_t *bytes, int size, uint64_t start,
  		      vector <Instruction *> &ins_list);
  
  vector <Instruction *> readIns(uint64_t start, uint64_t end);
  vector <Instruction *> getIns(uint64_t start, int ins_cnt);
  void createInsCache(uint64_t code_start, uint64_t code_end);
private:
  void handle_gaps (uint8_t * bytes, uint64_t addrs, int index, uint64_t size,
         vector <Instruction *> &ins_list);
  uint64_t disasmEnd(uint64_t start, uint64_t size);
};
#endif
