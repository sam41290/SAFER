#include "Instruction.h"
#include <exception>
#include "config.h"

using namespace SBI;


string
Instruction::prefixChk(char *mne) {
  string asm_opcode(mne);
  std::istringstream iss(mne);
  std::vector <std::string> results((std::istream_iterator
        <std::string>(iss)),std::istream_iterator <std::string>());
  if(results.size() > 1) {
    int i = 0;
    for(i = 0; i < (results.size() - 1); i++) {
      if(results[i] == "bnd")
        isBnd_ = true;
      prefix_ = results[i] + " ";
    }
    asm_opcode = results[i];
  }
/*
  if(results.size() > 1) {
    if(results[0] == "bnd")
      isBnd_ = true;
    //LOG("prefix: "<<results[0]);
    prefix_ = results[0] + " ";
    asm_opcode = results[1];
  }
  */
  return asm_opcode;
}

Instruction::Instruction(uint64_t address, char *mne, char *op_str,
			  uint8_t * bytes, int size) {
  location(address);
  insBinary(bytes, size);
  string asm_opcode = prefixChk(mne);
  string operand(op_str);
  //if(address == 0x139517)
  //DEF_LOG(hex<<address<<": "<<asm_opcode<<" "<<operand);
  set <string> cf_ins_set = utils::get_cf_ins_set();
  set <string> uncond_cf_ins_set = utils::get_uncond_cf_ins_set();
  if(asm_opcode.find(",") != string::npos) {
    vector <string> oplst = utils::split_string(asm_opcode,",");
    if(cf_ins_set.find(oplst[0]) != cf_ins_set.end())
      asm_opcode = oplst[0];
  }

  if(cf_ins_set.find(asm_opcode) != cf_ins_set.end()) {
    //isJump(true);
    sem_ = new JUMP(asm_opcode,operand,insBinary_,loc_,isBnd_);

    if(asm_opcode.find("ret") != string::npos) {
      isFuncExit(true);
      sem_-> isJump_ = true;
      sem_->isUnconditionalJmp_ = true;
      //sem_->fallThrgh_ = 0;
      sem_->target_ = 0;
    }
    else {
      if(sem_->isIndrctCf_ == false) {
        uint64_t tgt = sem_->target_;
        operand = "." + to_string(tgt);
      }
      else {
        atRequired_ = true;
        if(ENCODE == 1)
          decode(true);
      }
      if(asm_opcode == "jmpq")
        asm_opcode = "jmp";
      //LOG("Target: "<<hex<<tgt);
    }
  }
  else if(asm_opcode.find("lea") != string::npos && operand.length() > 0)
    sem_= new LEA(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("mov") != string::npos)
    sem_ = new MOV(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("add") != string::npos)
    sem_ = new ADD(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("sub") != string::npos)
    sem_= new ADD(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("push") != string::npos)
    sem_= new PUSH(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("pop") != string::npos)
    sem_ = new POP(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("and") != string::npos)
    sem_ = new AND(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("or") != string::npos)
    sem_ = new OR(asm_opcode,operand,insBinary_,loc_);
  else if(asm_opcode.find("xor") != string::npos)
    sem_ = new XOR(asm_opcode,operand,insBinary_,loc_);
  else 
    sem_ = new UNKNOWNINS(asm_opcode,operand,insBinary_,loc_);


  addOrigIns(asm_opcode);
  addOrigIns(operand);
  if(asm_opcode.find("xbegin") != string::npos) {
    //DEF_LOG("xbegin found: "<<hex<<location()<<" "<<operand);
    operand = "." + to_string(stoull(operand,0,16));
  }
  if(asm_opcode.find("rdrand") != string::npos)
    asm_opcode = "rdrand";
  
  //if(uncond_cf_ins_set.find(asm_opcode) != uncond_cf_ins_set.end()) 
  //  isUnconditionalJmp(true);
  //if(asm_opcode.find("call") != string::npos)
  //  isCall(true);

  if(asm_opcode.find("hlt") != string::npos){
    isHlt_ = true;
    isFuncExit(true);
  }
  if(asm_opcode.find("ud2") != string::npos){
    isHlt_ = true;
    isFuncExit(true);
  }

  label("." + to_string(address));
  mnemonic_ = asm_opcode;
  op1(operand);
  //isRltvAccess(address + size);
  //chkConstOp();
  //chkConstPtr();
  if(sem_->isRltvAccess_) {
    string lbl = "." + to_string(sem_->ripRltvOfft_);
    //op1_ = op1_.replace(offset_pos, pos - offset_pos, lbl);
    op1_ = utils::symbolizeRltvAccess(op1_,lbl,sem_->ripRltvOfft_,SymBind::NOBIND);
  }
  asmIns(prefix_ + asm_opcode + " " + op1_);
  //fallThrgh_ = address + size;  
  //LOG("Fall through: "<<hex<<fallThrgh_);
}
/*
bool isNumber(const string& str)
{
    if(str.length() <= 0)
      return false;
    for (char const &c : str) {
        if (std::isdigit(c) == 0) return false;
    }
    return true;
}

bool isHexNumber(string str)
{
  if(str.length() <= 0)
    return false;
  if(str.find("0x") == 0)
    str.replace(0,2,"");
  for (int i=0; i<str.length(); i++)
  {
    if (!isxdigit(str[i])) {
      return false;
    }
  }
  return true;
}

void
Instruction::chkConstOp() {

  vector <string> oplst = utils::split_string(op1_,",");
  if(mnemonic_.find(".byte") != string::npos)
    return;
  for(auto & s : oplst) {
    if(s.find("$") == 0) {
      s.replace(0,1,"");

      //DEF_LOG("Const op: "<<s);
      if(s.find("0x") != string::npos)
        constOp_ = stoull(s,0,16);
      else if(isNumber(s))
        constOp_ = stoull(s);
      else if(isHexNumber(s))
        constOp_ = stoull(s,0,16);
      break;
    }
    else if(isHexNumber(s)) {
      //DEF_LOG("hex const ptr: "<<hex<<location()<<": "<<asmIns()<<" const ptr: "<<s);
      constPtr_ = stoull(s,0,16);
      break;
    }
    else if(isNumber(s)) {
      //DEF_LOG("Dec const ptr: "<<hex<<location()<<": "<<asmIns()<<" const ptr: "<<s);
      //DEF_LOG(s<<" not a hex number");
      constPtr_ = stoull(s);
      break;
    }
  }
}

void
Instruction::chkConstPtr() {
  if(mnemonic_.find("lea") == string::npos && 
     op1_.find("(,") != string::npos) {
    //DEF_LOG("Checking for mem access: "<<hex<<location()<<":"<<mnemonic_<<" "<<op1_);
    vector <string> words =  utils::split_string(op1_,",");
    for(auto & w : words) {
      if(w.find("(") != string::npos) {
        if(w.find("%") == string::npos) {
          if(w.find("*") == 0)
            w.replace(0,1,"");
          else if(w.find(" ") == 0)
            w.replace(0,1,"");
          w.replace(w.find("("),1,"");
          if(w.length() > 0) {
            if(w.find("0x") != string::npos || utils::checkHex(w))
              constPtr_ = stoull(w,0,16);
            else
              constPtr_ = stoull(w);
          }
          //DEF_LOG("mem access: "<<hex<<constPtr_);
          break;
        }
        else
          break;
      }
    }
  }
}

uint64_t
Instruction::calcTarget() {


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

*/

bool
Instruction::indirectCFWithReg() {
  //DEF_LOG("Checking if indirect CF: "<<hex<<location());
  if(sem_->isIndrctCf_ == true && asmIns_.find("ret") == string::npos &&
      asmIns_.find("%rip") == string::npos && asmIns_.find("call") ==
      string::npos) {
      return true;
    }
  //DEF_LOG("Not an indirect CF");
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
    if(forcePrintAsm_ || 
      ((isJump() || isCall() || isRltvAccess()) && asmIns_.find("ret") == string::npos))
      asm_ins += "\t" + asmIns_ + "\n";
    else {
      for(auto byte : insBinary_)
        asm_ins += "\t.byte " + to_string((uint32_t)byte) + "\n";
    }
  }
  asm_ins += "\t" + instAsmPost_ + "\n";
  SymBind b = SymBind::NOBIND;
  if(location() != 0 && isCode())
    b = SymBind::FORCEBIND;
  utils::printAsm(asm_ins,location(),label_ + lbl_sfx,b,file_name);
  if(isCall() && asm_ins.find(fallSym() + ":") == string::npos) {
    utils::printLbl(fallSym(),file_name);
  }
}

void
Instruction::setInstParams(HookType h) {
  string operand = op1_;
  instParams_.clear();
  paramIns_.clear();
  instParams_.push_back("$0");
  paramIns_.push_back("mov");
  instParams_.push_back("$" + to_string(loc_));
  paramIns_.push_back("mov");
  if(sem_->isIndrctCf_) {
    DEF_LOG("Getting reg val: "<<asmIns_<<" "<<operand);
    //if(get_decode()) 
    //  instParams_[(int)InstArg::INDIRECT_TARGET] = getIcfReg(op1_);
    //else 
    {
      string operand = op1_;
      operand.replace(0,1,"");
      instParams_.push_back(getRegVal(operand,h));
    }
  }
  else
    instParams_.push_back("$0");
  paramIns_.push_back("mov");
  if(sem_->isLea_) {
    DEF_LOG("Getting reg val: "<<asmIns_<<" "<<operand);
    size_t pos = operand.find (",");
    string pointer = operand.substr(0, pos);
    pos = operand.find("%",pos);
    string reg = operand.substr(pos);
    instParams_.push_back(getRegVal(reg,h));
  }
  else
    instParams_.push_back("$0");
  paramIns_.push_back("mov");
  instParams_.push_back(getRegVal("%r8",h));
  instParams_.push_back(getRegVal("%r9",h));
  instParams_.push_back(getRegVal("%r10",h));
  instParams_.push_back(getRegVal("%r11",h));
  instParams_.push_back(getRegVal("%r12",h));
  instParams_.push_back(getRegVal("%r13",h));
  instParams_.push_back(getRegVal("%r14",h));
  instParams_.push_back(getRegVal("%r15",h));
  instParams_.push_back(getRegVal("%rdi",h));
  instParams_.push_back(getRegVal("%rsi",h));
  instParams_.push_back(getRegVal("%rbp",h));
  instParams_.push_back(getRegVal("%rbx",h));
  instParams_.push_back(getRegVal("%rdx",h));
  instParams_.push_back(getRegVal("%rax",h));
  instParams_.push_back(getRegVal("%rcx",h));
  instParams_.push_back(getRegVal("%rsp",h));
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
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto & tgt:targetPos) {
    HookType h = HookType::GENERAL_INST;
    if(tgt.first == InstPoint::ADDRS_TRANS)
      h = HookType::ADDRS_TRANS;
    else if(tgt.first == InstPoint::RET_CHK)
      h = HookType::RET_CHK;
    else if(tgt.first == InstPoint::SYSCALL_CHECK)
      h = HookType::SYSCALL_CHECK;
    setInstParams(h);
    vector<InstArg> allArgs= instArgs()[tgt.second];
    string args = "";
    if(tgt.first == InstPoint::ADDRS_TRANS) {
      //if(alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) ||
      //   alreadyInstrumented(InstPoint::SHSTK_FUNCTION_CALL))
       // continue;
      args += "mov " + instParams_[(int)InstArg::INDIRECT_TARGET] + ",%rax\n";
    }
    else if(tgt.first == InstPoint::RET_CHK) {
      if(asmIns_.find("ret") != string::npos)
        args += "pop %rax\n";
      else if(isCall()) {
        if(FULL_ADDR_TRANS)
          args += "lea ." + to_string(fallThrough()) + "(%rip),%rax\n";
        else
          args += encodeRet(fallThrough());
      }
      else if(isPltJmp()) {
        args += "mov 0(%rsp),%rax\n";
      }
    }
    //else if (tgt.first == InstPoint::SHSTK_FUNCTION_CALL) {
    //  args += fallSym();
    //  DEF_LOG("call arg is: " << args);
    //}
    else if(tgt.first == InstPoint::SHSTK_CANARY_EPILOGUE) {
      DEF_LOG("operand 2 is : " << op1());
      args += op1().substr(op1().find(",") + 1);
      DEF_LOG("args is : " << args);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_CHANGE)
      args += op1().substr(op1().find(",") + 1);
    else if(tgt.first == InstPoint::SHSTK_CANARY_PROLOGUE) {
      args += op1().substr(op1().find(",") + 1);
      auto offset = raOffset();
      //if(frameReg_ == "%rsp")
      //  offset += 8;
      //args = args + "," + to_string(offset) + "(" + frameReg_ + ")";
      args = args + "," + to_string(offset) + "," + frameReg_;
      DEF_LOG("args is : " << args);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_MOVE) {
      args += op1().substr(0,op1().find(","));
      DEF_LOG("args is : " << args);
    }
    else {
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
    }
    if(tgt.first == InstPoint::LEA_INS_POST)
      instAsmPost_ += generate_hook(tgt.second,args,mnemonic_);
    else if(tgt.first == InstPoint::ADDRS_TRANS) {
      DEF_LOG("Address translation: "<<hex<<location());
      asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::ADDRS_TRANS);
      forcePrintAsm_ = true;
    }
    else if(tgt.first == InstPoint::RET_CHK) {
      //DEF_LOG("Instrumenting returns: "<<hex<<loc_);
      if(isCall()) {
        //string fall_sym = label() + "_fall_" + to_string(fallctr_);
        instAsmPre_ = generate_hook(op1(),args,"call",HookType::RET_CHK,fallSym());
      }
      else if(isPltJmp())
        instAsmPre_ = generate_hook(op1(),args,mnemonic_,HookType::RET_CHK);
      else
        asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::RET_CHK);
      forcePrintAsm_ = true;
    }
    else if(tgt.first == InstPoint::LEGACY_SHADOW_STACK) {
      //DEF_LOG("Instrumenting returns: "<<hex<<loc_);
      if(isCall()) {
        if(sem_->isIndrctCf_ == false)
        //  instAsmPre_ = generate_hook(op1(),args,"call",HookType::LEGACY_SHADOW_INDRCT_CALL,fallSym());
        //else
          asmIns_ = generate_hook(op1(),args,"call",HookType::LEGACY_SHADOW_CALL,fallSym());
      }
      //else if(isJump())
      //  instAsmPre_ = generate_hook(tgt.second,args,mnemonic_,HookType::LEGACY_SHADOW_JMP);
      else
        instAsmPre_ = generate_hook(tgt.second,args,mnemonic_,HookType::LEGACY_SHADOW_RET);
      forcePrintAsm_ = true;
    }
    else if(tgt.first == InstPoint::SYSCALL_CHECK)
      instAsmPre_ = generate_hook(tgt.second,args,mnemonic_,HookType::SYSCALL_CHECK);
    //else if (tgt.first == InstPoint::SHSTK_FUNCTION_CALL) {
    //  if(isCall()) {
    //    //if(sem_->isIndrctCf_)
    //    //  asmIns_ = generate_hook(op1(),args,"call",HookType::SHSTK_INDRCT_CALL,fallSym());
    //    //else
    //    if(sem_->isIndrctCf_ == false)
    //      asmIns_ = generate_hook(op1(),args,"call",HookType::SHSTK_DRCT_CALL,fallSym());
    //  }
    //  else
    //    asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::LEGACY_SHADOW_RET);
    //  forcePrintAsm_ = true;
    //}
    else if (tgt.first == InstPoint::SHSTK_FUNCTION_RET) {
      instAsmPre_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_FUNCTION_RET);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_EPILOGUE) {
      DEF_LOG("Instrumenting canary checks: "<<args);
      asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_CANARY_EPILOGUE);
      forcePrintAsm_ = true;
      DEF_LOG("canary inst: "<<asmIns_);
    }
    else if(tgt.first == InstPoint::SHSTK_FUNCTION_ENTRY) {
      DEF_LOG("Instrumenting function entry for shstk: "<<args);
      if(asmIns_.find("endbr") != string::npos)
        instAsmPost_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_FUNCTION_ENTRY);
      else
        instAsmPre_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_FUNCTION_ENTRY);
      //forcePrintAsm_ = true;
      //DEF_LOG(hex<<location()<<": canary inst: "<< asmIns_);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_CHANGE) {
      DEF_LOG("Instrumenting canary checks: "<<args);
      asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_CANARY_CHANGE);
      forcePrintAsm_ = true;
      DEF_LOG(hex<<location()<<": canary inst: "<< asmIns_);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_PROLOGUE) {
      DEF_LOG("Instrumenting canary checks: "<<args);
      asmIns_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_CANARY_PROLOGUE);
      forcePrintAsm_ = true;
      DEF_LOG(hex<<location()<<": canary inst: "<< asmIns_);
    }
    else if(tgt.first == InstPoint::SHSTK_CANARY_MOVE) {
      DEF_LOG("Instrumenting canary checks: "<<args);
      instAsmPost_ = generate_hook(tgt.second,args,mnemonic_,HookType::SHSTK_CANARY_MOVE);
      //forcePrintAsm_ = true;
      DEF_LOG(hex<<location()<<": canary inst: "<< asmIns_);
    }
    else
      instAsmPre_ += generate_hook(tgt.second,args,mnemonic_);
  }
}

