#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include "libutils.h"
#include "instrument.h"

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
class Instruction : public Instrument, public ENCCLASS
{
private:
  uint64_t loc_;
  vector <uint8_t> insBinary_; //hex bytes of original Instruction
  uint64_t target_ = false;
  bool isJump_ = false;
  bool isUnconditionalJmp_ = false;
  bool isCall_ = false;
  bool isLea_ = false;
  bool isIndrctCf_ = false;
  int opCnt_;			//operand count
  string mnemonic_;
  string op1_;			//operands
  string op2_;
  string op3_;
  uint64_t fallThrgh_ = 0;
  bool isFuncExit_ = false;
  bool isRltvAccess_ = false;
  bool rltvOfftAdjusted_ = false;
  bool isHlt_ = false;
  uint64_t ripRltvOfft_ = 0;
  uint64_t constOp_ = 0;
  uint64_t constPtr_ = 0;
  string label_;
  string asmIns_;
  string prefix_ = "";
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
public:
  Instruction() {}
  Instruction(uint64_t address, char *mnemonic, char *op_str, uint8_t
	       * bytes, int size);
  string prefix() { return prefix_; }
  void instAsmPre(string code) { instAsmPre_ += code; }
  void location(uint64_t p_loc) { loc_ = p_loc;}
  bool isCode() { return isCode_; }
  void isCode(bool code) { isCode_ = code; }
  void encode (bool to_encode) { encode_ = to_encode; }
  bool encode () { return encode_; }
  void decode (bool to_decode) { decode_ = to_decode; }
  bool decode () { return decode_; }
  void
  isJump(bool is_jump) { isJump_ = is_jump;}
  bool isHlt() { return isHlt_; } 
  void mnemonic(string p_mnemonic) { mnemonic_ = p_mnemonic;}
  
  void
  isUnconditionalJmp(bool isUncdJmp) { isUnconditionalJmp_ = isUncdJmp; }
  
  void
  isCall(bool isCall) { isCall_ = isCall;}
  
  void
  isIndirectCf(bool is_indirect_cf) { isIndrctCf_ = is_indirect_cf;}
  
  void
  fallThrough(uint64_t fallThrough) { fallThrgh_ = fallThrough;}

  void
  addFallThroughJump(uint64_t chkaddrs, string labelprefix) {
    if(chkaddrs != fallThrgh_)
      asmIns(asmIns_ + "\njmp " + labelprefix + to_string(fallThrgh_));
  }

  void
  isFuncExit(bool funcExit) { isFuncExit_ = funcExit;}
  
  void
  op1(string p_op1) { op1_ = p_op1;}
  
  void
  op2(string p_op2) { op2_ = p_op2;}
  
  void
  op3(string p_op3) { op3_ = p_op3;}
  
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
  target() { return target_;}

  void
  target(uint64_t tgt) { target_ = tgt; }
  
  bool
  isJump() { return isJump_;}
  
  bool
  isUnconditionalJmp() { return isUnconditionalJmp_;}
  
  bool
  isCall() { return isCall_;}
  
  bool
  isIndirectCf() { return isIndrctCf_;}
  
  uint64_t
  fallThrough() { return fallThrgh_;}
  
  bool
  isFuncExit() { return isFuncExit_;}
  
  bool
  isRltvAccess() { return isRltvAccess_;}
  
  uint64_t
  ripRltvOfft() { return ripRltvOfft_;}

  void
  ripRltvOfft(uint64_t val) { ripRltvOfft_ = val; }
  
  int
  opCnt() { return opCnt_;}
  
  string
  op1() { return op1_;}
  
  string
  op2() { return op2_;}
  
  string
  op3() { return op3_;}
  
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
  isLea(bool isLea) { isLea_ = isLea; }
  
  bool
  isLea() { return isLea_; }

  uint64_t constOp() { return constOp_; }
  uint64_t constPtr() { return constPtr_; }
  string
  mnemonic() { return mnemonic_;} 
  vector <uint8_t> insBinary() { return insBinary_;}
  void rltvOfftAdjusted(bool b) { rltvOfftAdjusted_ = b; }
  bool rltvOfftAdjusted() { return rltvOfftAdjusted_; }
  void setInstParams();

  bool indirectCFWithReg();
  void print(string file_name,string lbl_sfx);
  void instrument();
  void chkConstOp();
  void isRltvAccess(int RIP);
  void setRltvAccess(bool val) { isRltvAccess_ = val; }
  void chkConstPtr();
private:
  uint64_t calcTarget();
  string prefixChk(char *mne);
};
}
#endif
