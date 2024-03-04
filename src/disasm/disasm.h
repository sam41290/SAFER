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
#define LIBOPCODES disassembleLibOpcodes

//#define DISASENGN CAPSTONE
//#define DISASENGN OBJDUMP
#define DISASENGN disassembleLibOpcodes

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
  unordered_set <uint64_t> invalid_;
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
    //csh handle_;
    //if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
    //  LOG("Error opening capstone handle");
    //  exit(0);
    //}
    //cs_option (handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
  }
  bool invalid (uint64_t addrs) {
    if(invalid_.find(addrs) != invalid_.end())
      return true;
    return false;
  }
  
  vector <Instruction *> getIns(uint64_t start, int ins_cnt);
private:
  void handle_gaps (uint8_t * bytes, uint64_t addrs, int index, uint64_t size,
         vector <Instruction *> &ins_list);
  uint64_t disasmEnd(uint64_t start, uint64_t size);
  void disassembleCaps (uint8_t *bytes, int size, uint64_t start,
  		       vector <Instruction *> &ins_list);
  void disassembleObj (uint8_t *bytes, int size, uint64_t start,
  		      vector <Instruction *> &ins_list);
  void disassembleLibOpcodes (uint8_t *bytes, size_t size, uint64_t start,
  		       vector <Instruction *> &ins_list);
  vector <Instruction *> readIns(uint64_t start, uint64_t end);
  void createInsCache(uint64_t code_start, uint64_t code_end);
  void superSetCache(uint64_t start, uint64_t end);
  uint8_t *getBytes(uint64_t start, uint64_t end);
};
#endif
