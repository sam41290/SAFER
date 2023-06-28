#ifndef _INSVALIDITY_H
#define _INSVALIDITY_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
#include "libanalysis.h"
#include "CfgElems.h"

using namespace std;

namespace SBI {

  enum class InsValidityRules {
    VLD_OP = 0,
    VLD_MEM,
    VLD_PRFX,
    VLD_USRMODE_INS
  };


  class CFValidity : public virtual CfgElems {
    static uint64_t memSpaceStart_;
    static uint64_t memSpaceEnd_;
    static bool (*InsValidators_[4])(Instruction *);
    static vector <InsValidityRules> insRule_;
    static unordered_set <uint64_t> invalidIns_;
    static unordered_set <uint64_t> validIns_;
  public:
    CFValidity(uint64_t strt, uint64_t end, 
               const vector <InsValidityRules> &ins_rules) {
      memSpaceStart_ = strt;
      memSpaceEnd_ = end;
      insRule_ = ins_rules;
      InsValidators_[(int)InsValidityRules::VLD_OP] = &validOpCode;
      InsValidators_[(int)InsValidityRules::VLD_MEM] = &validMem;
      InsValidators_[(int)InsValidityRules::VLD_PRFX] = &validPrfx;
      InsValidators_[(int)InsValidityRules::VLD_USRMODE_INS] = &validUsrModeIns;
    }
    static bool validAddrs(uint64_t addrs) {
      if(addrs >= memSpaceStart_ && addrs < memSpaceEnd_)
        return true;
      return false;
    }
    static bool validIns(vector <BasicBlock *> &bb_list);
    static bool validOpCode(Instruction *ins);
    static bool validMem(Instruction *ins);
    static bool validPrfx(Instruction *ins) {
      string asm_ins = ins->asmIns();
      vector <string> words = utils::split_string(asm_ins," ");
      for(auto & w : words) {
        if(utils::invalid_prefixes.find(w) != utils::invalid_prefixes.end())
          return false;
      }
      if(ins->asmIns().find("lock lea") != string::npos ||
        ((ins->isJump() || ins->isCall() || ins->asmIns().find("ret") != string::npos) && 
          ins->asmIns().find("lock") != string::npos)/* ||
         ins->asmIns().find("lock add") != string::npos*/)
        return false;
      /*
      for(auto & p : utils::invalid_prefixes)
        if(ins->mnemonic().find(p) != string::npos || ins->prefix().find(p) != string::npos)
          return true;
      */
      return true;
    }
    static bool validUsrModeIns(Instruction *ins) {
      if(utils::is_priviledged_ins(ins->asmIns())) {
        LOG("priviledged ins at: "<<hex<<ins->location());
        return false;
      }
      return true;
    }
    static bool validCFTransfer(vector <BasicBlock *> &bb_list);
    bool validCF(vector <BasicBlock *> &bb_list) { 
      return (zeroDefCodeConflict(bb_list) && validIns(bb_list) && validCFTransfer(bb_list));
    }
  private:
  };
}


#endif
