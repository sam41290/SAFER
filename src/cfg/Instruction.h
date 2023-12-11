#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include "libutils.h"
#include "instrument.h"
#include "InsDictionary.h"

/* Represents an assembly Instruction.
 * Contains Instruction specific properties and data members.
 */

#define PARAM1(args) paramIns_[(int)args[0]] + " " + instParams_[(int)args[0]]\
+ ",%rdi\n"
#define PARAM2(args) paramIns_[(int)args[1]] + " " + instParams_[(int)args[1]]\
+ ",%rsi\n" + PARAM1(args)
#define PARAM3(args) paramIns_[(int)args[2]] + " " + instParams_[(int)args[2]]\
+ ",%rdx\n" + PARAM2(args)
#define PARAM4(args) paramIns_[(int)args[3]] + " " + instParams_[(int)args[3]]\
+ ",%rcx\n" + PARAM3(args)
#define PARAM5(args) paramIns_[(int)args[4]] + " " + instParams_[(int)args[4]]\
+ ",%r8\n" + PARAM4(args)
#define PARAM6(args) paramIns_[(int)args[5]] + " " + instParams_[(int)args[5]]\
+ ",%r9\n" + PARAM5(args)

using namespace std;
namespace SBI {

class Instruction : public Instrument//, public virtual ENCCLASS
{
private:
  uint64_t loc_;
  vector <uint8_t> insBinary_; //hex bytes of original Instruction
  bool forcePrintAsm_ = false;
  int opCnt_;			//operand count
  string mnemonic_;
  string op1_;			//operands
  bool isFuncExit_ = false;
  bool rltvOfftAdjusted_ = false;
  bool isHlt_ = false;
  bool isPltJmp_ = false;
  int raOffset_ = 0;
  string frameReg_ = "%rsp";
  string label_;
  string asmIns_;
  string prefix_ = "";
  string fallSym_ = "";
  string fallBBSym_ = "";
  vector <string> data16_;
  vector <string> origIns_;
  bool isBnd_ = false;
  bool isCode_ = true;
  string instAsmPre_  = "";
  string instAsmPost_ = "";
  uint64_t insSize_ = 0;  
  vector<string> instParams_;
  vector<string> paramIns_;
  bool decode_ = false;
  bool encode_ = false;
  bool atRequired_ = false;
  bool canaryCheck_ = false;
  bool canaryAdd_ = false;
  int fallctr_ = 0;
  //bool addrTransMust_ = false;
  InsSemantics *sem_ = NULL;
public:
  Instruction() {
    sem_ = new SBI::UNKNOWNINS();
  }
  InsSemantics *sem() { return sem_; }
  string fallSym() { return fallSym_; }
  void fallSym(string sym) { fallSym_ = sym; }
  string fallBBSym() { return fallBBSym_; }
  void fallBBSym(string sym) { fallBBSym_ = sym; }
  void raOffset(uint64_t offt) { raOffset_ = offt; }
  void frameReg(string &reg) { frameReg_ = reg; }
  int raOffset() { return raOffset_; }
  void canaryCheck(bool chk) { canaryCheck_ = chk; }
  bool canaryCheck() { return canaryCheck_; }
  void canaryAdd(bool chk) { canaryAdd_ = chk; }
  bool canaryAdd() { return canaryAdd_; }
  //void addrTransMust(bool val) { addrTransMust_ = val; }
  //bool addrTransMust() { return addrTransMust_; }
  Instruction(uint64_t address, char *mnemonic, char *op_str, uint8_t
	       * bytes, int size);
  string prefix() { return prefix_; }
  void isPltJmp(bool val) { isPltJmp_ = val; }
  bool isPltJmp() { return isPltJmp_; }
  void atRequired(bool val) { atRequired_ = val; }
  bool atRequired() { return atRequired_; }
  void instAsmPre(string code) { instAsmPre_ += code; }
  void location(uint64_t p_loc) { loc_ = p_loc;}
  bool isCode() { return isCode_; }
  void isCode(bool code) { isCode_ = code; }
  void encode (bool to_encode) { encode_ = to_encode; }
  bool encode () { return encode_; }
  void decode (bool to_decode) { decode_ = to_decode; }
  bool decode () { return decode_; }
  void
  isJump(bool is_jump) { sem_->isJump_ = is_jump;}
  bool isHlt() { return isHlt_; } 
  void mnemonic(string p_mnemonic) { mnemonic_ = p_mnemonic;}
  
  //void
  //isUnconditionalJmp(bool isUncdJmp) { isUnconditionalJmp_ = isUncdJmp; }
  //
  //void
  //isCall(bool isCall) { isCall_ = isCall;}
  
  //void
  //isIndirectCf(bool is_indirect_cf) { isIndrctCf_ = is_indirect_cf;}
  //
  void
  fallThrough(uint64_t fallThrough) { sem_->fallThrgh_ = fallThrough;}

  void
  addFallThroughJump(uint64_t chkaddrs, string labelprefix) {
    if(chkaddrs != sem_->fallThrgh_)
      asmIns(asmIns_ + "\njmp " + labelprefix + to_string(sem_->fallThrgh_));
  }

  void
  isFuncExit(bool funcExit) { isFuncExit_ = funcExit;}
  
  void
  op1(string p_op1) { op1_ = p_op1;}
  
  //void
  //op2(string p_op2) { op2_ = p_op2;}
  //
  //void
  //op3(string p_op3) { op3_ = p_op3;}
  
  void
  label(string p_label) { label_ = p_label;}
  
  void
  asmIns(string p_asm_insn) { asmIns_ = p_asm_insn;}
  
  void
  insBinary(uint8_t * bytes, int size) {
    for(int i = 0; i <size; i++)
      insBinary_.push_back(bytes[i]);
  }
  
  void
  insBinary(vector <uint8_t> bytes) { insBinary_ = bytes;}

  void
  addData16(string p_data) { data16_.push_back(p_data);}
  
  void
  addOrigIns(string p_orig_insn) { 
    origIns_.push_back(p_orig_insn);
  }
  
  uint64_t
  location() { return loc_;}
  
  uint64_t
  target() { return sem_->target_;}

  //void
  //target(uint64_t tgt) { target_ = tgt; }
  
  bool
  isJump() { return sem_->isJump_;}
  
  bool
  isUnconditionalJmp() { return sem_->isUnconditionalJmp_;}
  
  bool
  isCall() { return sem_->isCall_;}
  
  bool
  isIndirectCf() { return sem_->isIndrctCf_;}
  
  uint64_t
  fallThrough() { return sem_->fallThrgh_;}
  
  bool
  isFuncExit() { return isFuncExit_;}
  
  bool
  isRltvAccess() { return sem_->isRltvAccess_;}
  
  uint64_t
  ripRltvOfft() { return sem_->ripRltvOfft_;}

  void
  ripRltvOfft(uint64_t val) { sem_->ripRltvOfft_ = val; }
  
  int
  opCnt() { return opCnt_;}
  
  string
  op1() { return op1_;}
  
  //string
  //op2() { return op2_;}
  //
  //string
  //op3() { return op3_;}
  
  string
  label() { return label_;}
  
  string
  asmIns() { return asmIns_;}
  
  vector <string> &originalIns() { return origIns_;}


  uint64_t
  insSize() {
    if(insSize_ == 0)
      insSize_ = insBinary_.size();
    return insSize_;
  }

  void insSize(uint64_t s) { insSize_ = s; }
  
  void
  isLea(bool isLea) { sem_->isLea_ = isLea; }
  
  bool
  isLea() { return sem_->isLea_; }

  uint64_t constOp() { return sem_->constOp_; }
  uint64_t constPtr() { return sem_->constPtr_; }
  string
  mnemonic() { return mnemonic_;} 
  vector <uint8_t> insBinary() { return insBinary_;}
  void rltvOfftAdjusted(bool b) { rltvOfftAdjusted_ = b; }
  bool rltvOfftAdjusted() { return rltvOfftAdjusted_; }
  void setInstParams(HookType h);

  bool indirectCFWithReg();
  void print(string file_name,string lbl_sfx);
  void instrument();
  //void chkConstOp();
  //void isRltvAccess(int RIP);
  void setRltvAccess(bool val) { sem_->isRltvAccess_ = val; }
  //void chkConstPtr();
  bool isCanaryPrologue() { return sem_->isCanaryPrologue(); }
  bool isCanaryEpilogue() { return sem_->isCanaryEpilogue(); }
private:
  //uint64_t calcTarget();
  string prefixChk(char *mne);
};
}
#endif
