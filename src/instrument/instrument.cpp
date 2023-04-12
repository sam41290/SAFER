#include "instrument.h"
#include "libutils.h"

const vector <string> savedReg_{"%rax","%rdi","%rsi","%rdx","%rcx","%r8","%r9","%r10","%r11"};
const vector <string> atfSavedReg_{};//{"%rax","%rdi","%rsi"};
const vector <string> syscallCheckSavedReg_{"%rax","%rdi", "%rsi", "%rdx"};

int ENCCLASS::decode_counter = 0;

/*
string
Instrument::leaInstrumentation (string mnemonic,string op1,uint64_t loc)
{
  string inst_code = "";
  size_t pos = op1.find (",");
  string pointer = op1.substr (0, pos);
  string reg = op1.substr (pos + 2);

  bool rdx_saved = false;
  string scratch_reg = "%rax";
  if (reg.compare (scratch_reg) == 0)
  {
    scratch_reg = "%rcx";
  }

  string new_reg = reg;
  if (reg.compare ("%rdx") != 0)
  {
    rdx_saved = true;
    inst_code += "\tpush %rdx\n";
  }
  else
  {
    inst_code += "\tpush %rcx\n";
    new_reg = "%rcx";
  }

  inst_code += "\tpush " + scratch_reg + "\n";
  inst_code += "\tmov " + reg + ",%rdx\n";
  inst_code += "\tmov $0x0010000000000001," + scratch_reg + "\n";
  inst_code += "\tmulx " + scratch_reg + "," + new_reg + "," + scratch_reg +
    "\n";
  inst_code += "\tpop " + scratch_reg + "\n";
  if (rdx_saved == true)
  {
    inst_code += "\tpop %rdx\n";
  }
  else
  {
    inst_code += "\tmov %rcx,%rdx\n";
    inst_code += "\tpop %rcx\n";
  }

  return inst_code;
}
*/
string
Instrument::getIcfReg(string op1) {
  string reg("-16(%rsp)");
  return reg;
}

/*
string
Instrument::icfInstrumentation (string mnemonic, string op1,uint64_t loc)
{
  op1.replace (0, 1, "");

  if (op1.find ("rsp") != string::npos)
    {
      int pos = op1.find ("(");
      uint64_t adjst = 0;
      if (pos != 0)
	    {
	      string off = op1.substr (0, pos);
	      adjst = stoi (off, 0, 16);
	    }
      adjst += 8;
      op1 = to_string (adjst) + "(%rsp)";
    }

  string inst_code = "";

  //inst_code += "\tpushf\n";
  inst_code += "\tpush %rax\n";
  inst_code += "\tmov " + op1 + ",%rax\n";
  inst_code += "\tmov %rax,-8(%rsp)\n";
  inst_code += "\tand $0xfff, %rax\n";
  inst_code += "\tshl $4,%rax\n";
  inst_code += "\txor -2(%rsp),%ax\n";
  inst_code += "\tmov %ax,-2(%rsp)\n";
  inst_code += "\tcmp $0,%ax\n";
  inst_code += "\tje .jump_loc_" + to_string (loc) + "\n";
  inst_code += ".addrs_trans_" + to_string (loc) + ":\n";
  //inst_code += "\tint3\n";
  inst_code += ".jump_loc_" + to_string (loc) + ":\n";
  inst_code += "\tpop %rax\n";
  //inst_code += "\tpopf\n";
  //inst_code += "\t" + mnemonic + " *-16(%rsp)\n";

  return inst_code;
}
*/


string 
Instrument::moveZeros(string op1, uint64_t loc, string file_name) {
  op1.replace (0, 1, "");
  string instCode = "";
  const char *exe = file_name.c_str();
  uint64_t exePtr = (uint64_t)exe;

  instCode += "mov " + op1 + ",-8(%rsp)\n" +
              "movw $0,-2(%rsp)\n" +
              "mov -8(%rsp)," + op1 + "\n";
  return instCode;
}


void 
Instrument::registerInstrumentation(InstPoint p,string
    func_name,vector<InstArg>argsLst) {
  targetPos_.push_back(make_pair(p,func_name));
  instFuncs_.push_back(func_name);
  instArgs_[func_name] = argsLst;
}

void
Instrument::registerInstrumentation(string fnName,string
    instCodeSymbol,vector<InstArg>argsLst) {
  targetFuncs_.push_back(make_pair(fnName,instCodeSymbol));
  instArgs_[instCodeSymbol] = argsLst;
  instFuncs_.push_back(instCodeSymbol);

}


void 
Instrument::registerInstrumentation(uint64_t tgtAddrs,string
    instCodeSymbol,vector<InstArg> argsLst) {
  targetAddrs_.push_back(make_pair(tgtAddrs,instCodeSymbol));
  instArgs_[instCodeSymbol] = argsLst;
  instFuncs_.push_back(instCodeSymbol);
}

string
Instrument::generate_hook(string hook_target, string args,
                          string mne,
                          HookType h, 
                          uint64_t sigaction_addrs) {

  /* Generates assembly code stub to be put at the instrumentation point
   *(basic block or function).
   *  The stub saves caller saved registers and flags.
   *  Then makes a call to the instrumentation code.
   */
  string inst_code = "";
  if(h == HookType::ADDRS_TRANS) {
    uint64_t rax_offt = 16;
    if(mne.find("call") != string::npos)
      rax_offt += 8;
    if(mne == "jmpq")
      mne = "jmp";
    //inst_code += "mov %rax,-" + to_string(rax_offt) + "(%rsp)\n"; 
    //inst_code += "mov %rax,%fs:0x88\n";
    //inst_code += args + mne + " ." + hook_target + "\n";
    inst_code += decodeIcf(hook_target,args,mne);
  }
  else if(h == HookType::RET_CHK) {
    uint64_t rax_offt = 8;
    mne = "jmp";
    inst_code += "mov %rax,%fs:0x88\n";
    //inst_code += "mov %rax,-" + to_string(rax_offt) + "(%rsp)\n"; 
    inst_code += args + mne + " ." + hook_target + "\n";
    DEF_LOG("Return check code: "<<inst_code);
  }
  else if(h == HookType::CANARY_EPILOGUE) {
    inst_code += "xor $0xdead," + args + "\n";
  }
  else if(h == HookType::CANARY_PROLOGUE) {
    inst_code += "xor $0xdead," + args + "\n";
  }
  else {
    inst_code += save(h);
    inst_code += args + "call ." + hook_target + "\n";
  }

  if(h == HookType::SEGFAULT) {
    /* If the stub is supposed to install seg-fault handler, we need to make
     * an additional call to sigaction system call.
     */
    inst_code = inst_code + "mov $11, %rdi\n" +
                            "mov %rax,%rsi\n" +
                            "mov $0, %rdx\n" +
                            "call ." + to_string(sigaction_addrs) + "_" + to_string(sigaction_addrs) + "_def_code\n";
  }
  //if(h == HookType::ADDRS_TRANS) {
  //  inst_code += "mov %rax,-8(%rsp)\n";
  //}

  if(h != HookType::ADDRS_TRANS 
     && h != HookType::RET_CHK
     && h != HookType::CANARY_EPILOGUE
     && h != HookType::CANARY_PROLOGUE)

    inst_code = inst_code + restore(h);
  //if(h == HookType::ADDRS_TRANS) {
  //  inst_code += mne + " *-40(%rsp)\n";
  //}
  return inst_code;
}

string
Instrument::save(HookType h) {
  string ins = "";

  vector <string> reg_list;
  if(h == HookType::ADDRS_TRANS)
    reg_list = atfSavedReg_;
  //else if(h == HookType::SYSCALL_CHECK)
  //  reg_list = syscallCheckSavedReg_;
  else
    reg_list = savedReg_;
  ins += "pushf\n";
  auto offset = 8 * reg_list.size();
  ins += "sub $" + to_string(offset) + ",%rsp\n";
  for(string & str : reg_list) {
    offset -= 8;
    ins += "mov " + str + "," + to_string(offset) + "(%rsp)\n";
    /*
    if(str == "flags")
      ins += "pushf\n";
    else
      ins+= "push " + str + "\n";
      */
  }
  return ins;
}

string
Instrument::restore(HookType h) {
  string ins = "";
  vector <string> reg_list;
  if(h == HookType::ADDRS_TRANS)
    reg_list = atfSavedReg_;
  //else if(h == HookType::SYSCALL_CHECK)
  //  reg_list = syscallCheckSavedReg_;
  else
    reg_list = savedReg_;

  auto it = reg_list.end();
  auto offset = 0;//8 * reg_list.size();
  while(it != reg_list.begin()) {
    it = prev(it);
    ins += "mov " + to_string(offset) + "(%rsp)," + *it + "\n";
    offset += 8;
    /*
    if(*it == "flags")
      ins += "popf\n";
    else
      ins+= "pop " + *it + "\n";
      */
  }
  ins += "add $" + to_string(8 * reg_list.size()) + ",%rsp\n";
  ins += "popf\n";
  return ins;
}

string
Instrument::getRegVal(string reg, HookType h) {

  vector <string> reg_list;
  if(h == HookType::ADDRS_TRANS)
    return reg;
    //reg_list = atfSavedReg_;
  //else if(h == HookType::SYSCALL_CHECK)
  //  reg_list = syscallCheckSavedReg_;
  else
    reg_list = savedReg_;
  string val = "";
  int offt = 8 * (reg_list.size() - 1);
  if(reg == "%rsp") {
    val += to_string(offt) + "(%rsp)";
    return val;
  }
  else if (reg.find ("rsp") != string::npos) {
    int pos = reg.find ("(");
    uint64_t adjst = 0;
    if (pos != 0) {
      string off = reg.substr (0, pos);
      adjst = stoi (off, 0, 16);
      //cout << "rsp offset: " << off << " adjst: " << adjst << endl;
    }
    adjst += (8 * (reg_list.size() + 1/*For pushf*/));
    //cout << "new adjustment: " << adjst << endl;
    val = to_string (adjst) + "(%rsp)";
    return val;
  }

  for(string & str:reg_list) {
    if(reg == str) {
      val += to_string(offt) + "(%rsp)";
      return val;
    }
    offt -= 8;
  }
  return reg;
}
