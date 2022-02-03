#include "Instruction.h"
#include <exception>
#include "config.h"

using namespace SBI;

string
Instruction::prefixChk(char *mne) {
  //LOG("Checking prefix: "<<mne);
  string asm_opcode(mne);
  std::istringstream iss(mne);
  std::vector <std::string> results((std::istream_iterator
        <std::string>(iss)),std::istream_iterator <std::string>());

  if(results.size() > 1) {
    if(results[0] == "bnd")
      isBnd_ = true;
    //LOG("prefix: "<<results[0]);
    prefix_ = results[0] + " ";
    asm_opcode = results[1];
  }
  return asm_opcode;
}

Instruction::Instruction(uint64_t address, char *mne, char *op_str,
			  uint8_t * bytes, int size) {
  location(address);
  insBinary(bytes, size);
  string asm_opcode = prefixChk(mne);
  string operand(op_str);
  //LOG(hex <<address <<": mnemonic: " <<asm_opcode <<" operand: " <<
  //     operand<<" size:"<<dec<<size);

  set <string> cf_ins_set = utils::get_cf_ins_set();
  set <string> uncond_cf_ins_set = utils::get_uncond_cf_ins_set();

  if(cf_ins_set.find(asm_opcode) != cf_ins_set.end()) {
    isJump(true);
    if(operand.length()> 0) {
      if(operand.find("*") != string::npos) {
        isIndirectCf(true);
        if(ENCODE == 1)
          decode(true);
      }
      else if(asm_opcode.find("ret") != string::npos) {
        isFuncExit(true);
        isJump(true);
        isUnconditionalJmp(true);
        fallThrgh_ = 0;
        target_ = 0;
      }
      else {
        uint64_t tgt = calcTarget();
        operand = "." + to_string(tgt);
        //LOG("Target: "<<hex<<tgt);
      }
    }

  }
  addOrigIns(asm_opcode);
  addOrigIns(operand);
  if(asm_opcode.find("xbegin") != string::npos)
    operand = "." + to_string(stoull(operand,0,16));
  if(asm_opcode.find("rdrand") != string::npos)
    asm_opcode = "rdrand";
  
  if(uncond_cf_ins_set.find(asm_opcode) != uncond_cf_ins_set.end()) 
    isUnconditionalJmp(true);
  if(asm_opcode.find("call") != string::npos)
    isCall(true);

  if(asm_opcode.find("hlt") != string::npos){
    isHlt_ = true;
    isFuncExit(true);
  }

  label("." + to_string(address));
  mnemonic_ = asm_opcode;
  op1(operand);
  isRltvAccess(address + size);
  chkConstOp();
  asmIns(prefix_ + asm_opcode + " " + op1_);
  fallThrgh_ = address + size;  
}

void
Instruction::chkConstOp() {

  vector <string> oplst = utils::split_string(op1_,',');
  for(auto & s : oplst) {
    if(s.find("$") == 0) {
      s.replace(0,1,"");

      //LOG("Const op: "<<s);
      if(s.find("0x") != string::npos || utils::checkHex(s))
        constOp_ = stoull(s,0,16);
      else
        constOp_ = stoull(s);
      break;
    }
  }
}

uint64_t
Instruction::calcTarget() {

  /* Calculates the jump target_ from hex bytes of the Instruction.
   */

  string hex_target = "";
  int j = insBinary_.size();
  int inssz = j;
  int opCnt_ = 0;
  //cout<<"ins size: "<<inssz<<endl;
  int64_t tgt = 0;
  int64_t next_loc = loc_ + inssz;
  if(isBnd_)
    inssz--;

  if(inssz < 5) {
    opCnt_ = 1;
    for(int i = 1; i <= opCnt_; i++) {
      string hex = utils::decToHexa(insBinary_[j - i]);
      //cout<<"hex byte: "<<hex<<endl;
      hex_target += hex;
      //cout<<"hex offset: "<<hex_target<<endl;
    }
    //int64_t next_loc = loc_ + inssz;
    int8_t offset;

    offset = stoi(hex_target, 0, 16);
    tgt = abs(next_loc + offset);
  }
  else {
    opCnt_ = 4;
    if(inssz < 5) {
      LOG("Invalid jump ins at: "<<loc_);
      exit(0);
    }
    for(int i = 1; i <= opCnt_; i++) {
      string hex = utils::decToHexa(insBinary_[j - i]);
      //cout<<"hex byte: "<<hex<<endl;
      hex_target += hex;
      //cout<<"hex offset: "<<hex_target<<endl;
    }
    //int64_t next_loc = loc_ + inssz;
    int32_t offset = stol(hex_target, 0, 16);
    tgt = abs(next_loc + offset);
  }
  target_ = tgt;
  return target_;
}


void
Instruction::isRltvAccess(int RIP) {

  //LOG("Checking RIP relative access for ins: "<<hex<<loc_<<" operand "<<op1_);
  if(op1_.size()> 0) {
    //check for RIP relative access and convert them to labels.
    int pos = op1_.find("(%rip)");
    if(pos != string::npos) {
      isRltvAccess_ = true;
      int base = 16;
      int offset_pos = origIns_[1].rfind("0x", pos);

      if(offset_pos == string::npos) {
        offset_pos = op1_.rfind(".", pos);
        if(offset_pos == string::npos) {
          offset_pos = op1_.rfind(" ", pos);
          if(offset_pos == string::npos) {
            offset_pos = op1_.rfind(",", pos);
            if(offset_pos == string::npos)
              offset_pos = 0;
          }
        }
        else
          base = 10;
      }
      int comma_pos = origIns_[1].rfind(",", pos);
      if(comma_pos != string::npos && comma_pos > offset_pos && comma_pos < pos)
        offset_pos = comma_pos;
      if(offset_pos != 0) {
        if(op1_.substr(offset_pos - 1, 1) == "-") {
          offset_pos = offset_pos - 1;
        }
      }

      if(offset_pos == string::npos || pos == string::npos) {
        LOG("incorect RIP parsing: " <<mnemonic_ <<" " <<op1_);
        exit(0);
      }
      uint64_t offset;
      if((pos - offset_pos) == 0)
        offset = 0;
      else {
        string off = op1_.substr(offset_pos, pos - offset_pos);
        try {
          offset = stol(off, 0, base);
        }
        catch(exception & e) {
          LOG("failed to get RIP rltv offset: " <<mnemonic_ <<" " <<
           op1_);
          //exit(0);
          offset = 0;
        }
      }
      ripRltvOfft_ = offset + RIP;
      //LOG("Ins :"<<hex<<loc_<<" rip offset: "<<hex<<ripRltvOfft_);
      if(mnemonic_.find("lea") != string::npos)
        isLea_ = true;
      string lbl = "." + to_string(ripRltvOfft_);
      op1_ = op1_.replace(offset_pos, pos - offset_pos, lbl);
    }
    asmIns_ = mnemonic_ + " " + op1_;

    //assm = assm + " " + ins.full_insn[2];
  }
}



bool
Instruction::indirectCFWithReg() {
  if(isIndrctCf_ == true && asmIns_.find("ret") == string::npos &&
      asmIns_.find("%rip") == string::npos && asmIns_.find("call") ==
      string::npos) {
      return true;
    }

  return false;
}


void
Instruction::print(string file_name, string lbl_sfx) {
  instrument();

  string asm_ins = "\t" + instAsmPre_ + "\n";
  if(mnemonic_ == "jrcxz") {
    asm_ins += "\tcmp $0, %rcx\n\tje " + op1_ + "\n";
  }
  else {
    if((isJump_ || isCall_ || isRltvAccess_)
        && asmIns_.find("ret") == string::npos)
      asm_ins += "\t" + asmIns_ + "\n";
    else {
      for(auto byte : insBinary_)
        asm_ins += "\t.byte " + to_string((uint32_t)byte) + "\n";
    }
  }
  asm_ins += "\t" + instAsmPost_ + "\n";
  SymBind b = SymBind::NOBIND;
  if(isCode())
    b = SymBind::FORCEBIND;
  utils::printAsm(asm_ins,location(),label_ + lbl_sfx,b,file_name);
}

void
Instruction::setInstParams() {
  string operand = op1_;
  instParams_.push_back("$0");
  paramIns_.push_back("mov");
  instParams_.push_back("$" + to_string(loc_));
  paramIns_.push_back("mov");
  if(isIndrctCf_) {
    //if(get_decode()) 
    //  instParams_[(int)InstArg::INDIRECT_TARGET] = getIcfReg(op1_);
    //else 
    {
      string operand = op1_;
      operand.replace(0,1,"");
      instParams_.push_back(getRegVal(operand));
    }
  }
  else
    instParams_.push_back("$0");
  paramIns_.push_back("mov");
  if(isLea_) {
    size_t pos = operand.find (",");
    string pointer = operand.substr(0, pos);
    string reg = operand.substr(pos + 2);
    instParams_.push_back(getRegVal(reg));
  }
  else
    instParams_.push_back("$0");
  paramIns_.push_back("mov");
  instParams_.push_back(getRegVal("%r8"));
  instParams_.push_back(getRegVal("%r9"));
  instParams_.push_back(getRegVal("%r10"));
  instParams_.push_back(getRegVal("%r11"));
  instParams_.push_back(getRegVal("%r12"));
  instParams_.push_back(getRegVal("%r13"));
  instParams_.push_back(getRegVal("%r14"));
  instParams_.push_back(getRegVal("%r15"));
  instParams_.push_back(getRegVal("%rdi"));
  instParams_.push_back(getRegVal("%rsi"));
  instParams_.push_back(getRegVal("%rbp"));
  instParams_.push_back(getRegVal("%rbx"));
  instParams_.push_back(getRegVal("%rdx"));
  instParams_.push_back(getRegVal("%rax"));
  instParams_.push_back(getRegVal("%rcx"));
  instParams_.push_back(getRegVal("%rsp"));
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("mov");
  paramIns_.push_back("lea");

  instParams_.push_back(exeNameLabel() + "(%rip)");
  paramIns_.push_back("lea");
   
}

void
Instruction::instrument() {  
  setInstParams();
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto tgt:targetPos) {
    vector<InstArg> allArgs= instArgs()[tgt.second];
    string args = "";
    switch(allArgs.size()) {
      case 0:
        break;
      case 1:
        args += PARAM1(allArgs);
        break;
      case 2:
        args += PARAM2(allArgs);
        break;
      case 3:
        args += PARAM3(allArgs);
        break;
      case 4:
        args += PARAM4(allArgs);
        break;
      case 5:
        args += PARAM5(allArgs);
        break;
      case 6:
        args += PARAM6(allArgs);
        break;
      default:
        args += PARAM6(allArgs);
        break;
    }
    if(tgt.first == InstPoint::LEA_INS_POST)
      instAsmPost_ += generate_hook(tgt.second,false,0,args);
    else
      instAsmPre_ += generate_hook(tgt.second,false,0,args);
  }
}
