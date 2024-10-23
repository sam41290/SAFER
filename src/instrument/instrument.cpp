#include "instrument.h"
#include "libutils.h"

const vector <string> savedReg_{"%rax","%rdi","%rsi","%rdx","%rcx","%r8","%r9","%r10","%r11"};
const vector <string> atfSavedReg_{};//{"%rax","%rdi","%rsi"};
//const vector <string> syscallCheckSavedReg_{"%rax","%rdi", "%rsi", "%rdx"};

int ENCCLASS::decode_counter = 0;
int Instrument::counter = 0;
vector <string> Instrument::instFuncs_ {};

string
Instrument::getIcfReg(string op1) {
  string reg("-16(%rsp)");
  return reg;
}

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
Instrument::registerInstrumentation(InstPoint p,InstPos pos, string func_name) {
  DEF_LOG("Registering instrumentation: "<<(int)p<<" "<<func_name);

  InstUnit i;
  i.instType_ = HookType::CALL_BASED_INST;
  i.instCode_ = func_name;
  i.pos_ = pos;

  targetPos_.push_back(make_pair(p,i));
  instFuncs_.push_back(func_name);
  //instArgs_[func_name] = argsLst;
}

void 
Instrument::registerInstrumentation(InstPoint p,InstPos pos, string func_name,
                                    vector<InstArg>argsLst) {
  DEF_LOG("Registering instrumentation: "<<(int)p<<" "<<func_name);

  InstUnit i;
  i.instType_ = HookType::CALL_BASED_INST;
  i.instCode_ = func_name;
  i.args_ = argsLst;
  i.pos_ = pos;

  targetPos_.push_back(make_pair(p,i));
  instFuncs_.push_back(func_name);
  //instArgs_[func_name] = argsLst;
}

void
Instrument::registerInstrumentation(string tgt_fn,string inst_code,
                                    vector<InstArg>args_lst) {
  InstUnit i;
  i.instType_ = HookType::CALL_BASED_INST;
  i.instCode_ = inst_code;
  i.args_ = args_lst;
  i.pos_ = InstPos::PRE;
  targetFuncs_.push_back(make_pair(tgt_fn,i));
  //instArgs_[instCodeSymbol] = argsLst;
  instFuncs_.push_back(inst_code);

}

void
Instrument::registerInstrumentation(InstPoint p, InstUnit &u) {
  targetPos_.push_back(make_pair(p,u));
}

void 
Instrument::registerInlineInstrumentation(string asm_str,InstPos p, InstPoint pnt) {
  InstUnit i;
  i.instType_ = HookType::INLINE_INST;
  i.instCode_ = asm_str;
  i.pos_ = p;
  targetPos_.push_back(make_pair(pnt,i));
}
void 
Instrument::registerInlineInstrumentation(string asm_str,InstPos p) {
  InstUnit i;
  i.instType_ = HookType::INLINE_INST;
  i.instCode_ = asm_str;
  i.pos_ = p;
  auto pnt = InstPoint::CUSTOM;
  targetPos_.push_back(make_pair(pnt,i));
}
void 
Instrument::registerInbuiltInstrumentation(InstPoint p) {
  InstUnit i;
  i.instType_ = HookType::PREDEF_INST;
  i.instCode_ = "";
  auto pnt = p;
  targetPos_.push_back(make_pair(pnt,i));
}

string
Instrument::directCallShstkTramp() {
  string inst_code = "";
  inst_code += "endbr64\n";
  //inst_code += "cmp $0, %fs:0x78\n";
  //inst_code += "jne .push_ra_" + to_string(counter) + "\n";
  //inst_code += "call .init_shstk\n";
  inst_code += ".push_ra_" + to_string(counter) + ":\n";
  if(alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY)) {
    inst_code += "push %r10\n";
    inst_code += "push %r11\n";
  }
  inst_code += "mov %fs:0x78,%r11\n";
  if(alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY)) {
    inst_code += "mov 16(%rsp),%r10\n";
  }
  else {
    inst_code += "mov 0(%rsp),%r10\n";
  }
  inst_code += "mov %r10,(%r11)\n";
  inst_code += "addq $8,%fs:0x78\n";
  if(alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY)) {
    inst_code += "pop %r11\n";
    inst_code += "pop %r10\n";
  }
  inst_code += ".actual_entry_" + to_string(counter) + ":\n";
  counter++;
  return inst_code;
}

string
Instrument::shadowRetInst(string &reg1, string &reg2, int free_reg_cnt) {
  string inst_code = "";
  string pro = "", epi = "";
  //int ra_offt = 0;
  if(free_reg_cnt == 0) {
    reg1 = "%r10";
    reg2 = "%r11";
    //ra_offt = 16;
    pro = "push %r10\npush %r11\n";
    epi = "pop %r11\npop %r10\n";
  }
  else if(free_reg_cnt == 1) {
    reg2 = "%r11";
    //ra_offt = 8;
    pro = "push %r11\n";
    epi = "pop %r11\n";
  }
  inst_code = inst_code + pro + 
              "mov %fs:0x78," + reg1 + "\n" +
              "mov 16(%rsp)," + reg2 + "\n" +
              ".rep_pop_" + to_string(counter) + ":\n" +
              "sub $8, " + reg1 + "\n" +
              "cmp (" + reg1 + ")," + reg2 + "\n" +
              "jne .rep_pop_" + to_string(counter) + "\n" +
              "mov " + reg1 + ", %fs:0x78\n" +
              epi;
  counter++;
  return inst_code;
}

string
Instrument::predefInstCode(InstPoint h, string mne, string fall_sym, 
                           string hook_target, string args) {
  string inst_code = "";
  if(h == InstPoint::ADDRS_TRANS) {
    uint64_t rax_offt = 16;
    if(mne.find("call") != string::npos)
      rax_offt += 8;
    if(mne == "jmpq")
      mne = "jmp";
    inst_code += decodeIcf("GTF_reg",args,mne);
  }
  else if(h == InstPoint::LEGACY_SHADOW_CALL) {
    //inst_code += "movq $0, %fs:0x80\n";
    inst_code += mne + " " + hook_target + "\n";
    if(mne.find("call") != string::npos)
      inst_code += fall_sym + ":\n";
  }
  //else if(h == InstPoint::LEGACY_SHADOW_INDRCT_CALL) {
  //}
  //else if(h == InstPoint::LEGACY_SHADOW_JMP) {
  //}
  else if(h ==  InstPoint::LEGACY_SHADOW_RET) {
    inst_code = inst_code + 
                "push %r10\n" +
                "push %r11\n" +
                "mov %fs:0x78,%r11\n" +
                "mov 16(%rsp),%r10\n" +
                ".rep_pop_" + to_string(counter) + ":\n" +
                "sub $8, %r11\n" +
                "cmp (%r11),%r10\n" +
                "jne .rep_pop_" + to_string(counter) + "\n" +
                "mov %r11, %fs:0x78\n" +
                "pop %r11\n" +
                "pop %r10\n";
    counter++;
  }
  else if(h == InstPoint::RET_CHK) {
    if(mne.find("call") != string::npos) {

      inst_code += "mov %rax,%fs:0x88\n";

      if(hook_target.find("*") != string::npos) {
        string op = hook_target;
        op.replace(0,1,"");
        inst_code += "mov " + op + ",%rax\n"
                  + "push %rdx\n"
                  + "lea .loader_map_start(%rip),%rdx\n" 
                  + "cmp (%rdx),%rax\n"
                  + "jl  .vdso_check_ret_check_" + to_string(counter) + "\n"
                  + "lea .loader_map_end(%rip),%rdx\n" 
                  + "cmp (%rdx),%rax\n"
                  + "jl  .false_call_" + to_string(counter) + "\n"
                  + ".vdso_check_ret_check_" + to_string(counter) + ":\n"
                  + "lea .vdso_start(%rip),%rdx\n" 
                  + "cmp (%rdx),%rax\n"
                  + "jl  .push_old_ra_" + to_string(counter) + "\n"
                  + "lea .vdso_end(%rip),%rdx\n" 
                  + "cmp (%rdx),%rax\n"
                  + "jl  .false_call_" + to_string(counter) + "\n";
        inst_code += ".push_old_ra_" + to_string(counter) + ":\n";
        inst_code += "pop %rdx\n";
        inst_code += args + "push %rax\n";
        inst_code += "mov %fs:0x88,%rax\n";
        inst_code += "jmp .actual_ins_ret_chk_" + to_string(counter) + "\n";
        inst_code += ".false_call_" + to_string(counter) + ":\n";
        inst_code += "pop %rdx\n";
        inst_code += "mov %fs:0x88,%rax\n";
        inst_code += "call " + hook_target + "\n";
        inst_code += "jmp " + fall_sym + "\n";
        inst_code += ".actual_ins_ret_chk_" + to_string(counter) + ":\n";
        if (op.find ("rsp") != string::npos) {
          int pos = op.find ("(");
          uint64_t adjst = 0;
          if (pos != 0)
          {
            string off = op.substr (0, pos);
            adjst = stoi (off, 0, 16);
          }
          adjst += 8;
          op = to_string (adjst) + "(%rsp)";
          string icf_args = "mov " + op + ",%rax\n";
          inst_code += decodeIcf("GTF_reg",icf_args,"jmp");

        }
        counter++;

      }
      else {
        inst_code += args + "push %rax\n";
        inst_code += "mov %fs:0x88,%rax\n";
      }
    }
    else if(mne.find("jmp") != string::npos) {
      string op = hook_target;
      op.replace(0,1,"");
      inst_code += "mov %rax,%fs:0x88\n";
      inst_code += "mov " + op + ",%rax\n"
                + "push %rdx\n"
                + "lea .loader_map_start(%rip),%rdx\n" 
                + "cmp (%rdx),%rax\n"
                + "jl  .vdso_check_ret_check_" + to_string(counter) + "\n"
                + "lea .loader_map_end(%rip),%rdx\n" 
                + "cmp (%rdx),%rax\n"
                + "jl  .false_call_" + to_string(counter) + "\n"
                + ".vdso_check_ret_check_" + to_string(counter) + ":\n"
                + "lea .vdso_start(%rip),%rdx\n" 
                + "cmp (%rdx),%rax\n"
                + "jl  .continue_plt_" + to_string(counter) + "\n"
                + "lea .vdso_end(%rip),%rdx\n" 
                + "cmp (%rdx),%rax\n"
                + "jg  .continue_plt_" + to_string(counter) + "\n";
      inst_code += ".false_call_" + to_string(counter) + ":\n";
      inst_code += "mov 8(%rsp),%rax\n";
      inst_code += "call .GTF_decode_rax\n";
      inst_code += "mov %rax,8(%rsp)\n";
      inst_code += ".continue_plt_" + to_string(counter) + ":\n";
      inst_code += "pop %rdx\n";
      inst_code += "mov %fs:0x88,%rax\n";

      counter++;
    }
    else {
      uint64_t rax_offt = 8;
      mne = "jmp";
      //inst_code += "mov %rax,%fs:0x88\n";
      //inst_code += "mov %rax,-" + to_string(rax_offt) + "(%rsp)\n"; 
      //inst_code += args + mne + " ." + hook_target + "\n";
      inst_code += decodeRet("GTF_stack",args,mne);
      DEF_LOG("Return check code: "<<inst_code);
    }
  }
  else if(h == InstPoint::SHSTK_INDIRECT_JMP) {
    inst_code = inst_code + "sub $8, %fs:0x78\n";
  }
  else if (h == InstPoint::SHSTK_FUNCTION_RET) {
    //inst_code = inst_code +
    //            "push %r11\n" +
    //            "sub $8, %fs:0x78\n" +
    //            "mov %fs:0x78,%r11\n" +
    //            "mov (%r11),%r11\n" +
    //            "mov %r11,8(%rsp)\n" +
    //            "pop %r11\n" +
    //            "ret\n";


    inst_code = inst_code + 
                "push %r10\n" +
                "push %r11\n" +
                "sub $8, %fs:0x78\n" +
                "mov %fs:0x78,%r11\n" +
                "mov (%r11),%r11\n" +
                "movq 16(%rsp),%r10\n" +
                "cmpq %r11,%r10\n" + args + "\n" +
                "jne .safe_ret_" + to_string(counter) + "\n" +
                "pop %r11\n" +
                "pop %r10\n" +
                "ret\n" +
                ".safe_ret_" + to_string(counter) + ":\n" +
                "hlt\n";
    counter++;
  }
  else if(h == InstPoint::SHSTK_FUNCTION_ENTRY) {
    inst_code = inst_code +
                "mov %fs:0x78, %r11\n"
                ".shstk_ok_" + to_string(counter) +  ":\n" +
                "mov (%rsp), %r10\n" +
                "movq %r10,(%r11)\n";
    counter++;
  }
  else if(h == InstPoint::SHSTK_CANARY_CHANGE) {
    string ca_reg = args;
    inst_code = inst_code + 
                "movq %fs:0x78," + ca_reg + "\n" +
                "xorq %fs:0x28," + ca_reg + "\n";
  }
  else if(h == InstPoint::SHSTK_CANARY_PROLOGUE) {
    vector <string> words = utils::split_string(args,",");
    if(words.size() >= 3) {
      string ca_reg = words[0];
      string ra_offt = words[1]; 
      string frame_reg = words[2];
      string extra_reg = "%r10";
      string mov_ra = "";
      string mov_rsp = "";
      if(ca_reg.find("r10") != string::npos) {
        extra_reg = "%r9";
      }
      if(frame_reg.find("(%rsp)") != string::npos) {
        auto pos = frame_reg.find("(");
        string rsp_offt = frame_reg.substr(0, pos);
        int rsp_offt_int = stoi(rsp_offt);
        rsp_offt_int += 8;
        mov_ra = "movq " + to_string(rsp_offt_int) + "(%rsp)," + extra_reg +
          "\nmovq " + ra_offt + "(" + extra_reg + ")," + extra_reg;
        mov_rsp = "movq " + to_string(rsp_offt_int) + "(%rsp)," + extra_reg +
          "\nlea " + ra_offt + "(" + extra_reg + ")," + extra_reg;
      }
      else if(frame_reg.find("%rsp") != string::npos) {
        int ra_offt_int = stoi(ra_offt);
        ra_offt_int += 8;
        mov_ra = "movq " + to_string(ra_offt_int) + "(" + frame_reg + ")," + extra_reg;
        mov_rsp = "lea " + to_string(ra_offt_int) + "(" + frame_reg + ")," + extra_reg;
      }
      else {
        mov_ra = "movq " + ra_offt + "(" + frame_reg + ")," + extra_reg;
        mov_rsp = "lea " + ra_offt + "(" + frame_reg + ")," + extra_reg;
      }
      inst_code = inst_code +
                  "mov %fs:0x78," + ca_reg + "\n" +
                  "cmpq $0," + ca_reg + "\n" +
                  "jg .shstk_ok_" + to_string(counter) + "\n" +
                  ".init_sh_" + to_string(counter) +  ":\n" +
                  "callq .init_shstk\n" +
                  "mov %fs:0x78," + ca_reg + "\n" +
                  ".shstk_ok_" + to_string(counter) +  ":\n" +
                  //"cmp %rsp,(" + ca_reg + ")\n" +
                  //"je .add_copy_canary_" + to_string(counter) +  "\n" +
                  //"cmp %rsp,-16(" + ca_reg + ")\n" +
                  //"je .copy_canary_" +  to_string(counter) +  "\n" +
                  "pushq " + extra_reg + "\n" + mov_ra + "\n" +
                  "movq " + extra_reg + ",(" + ca_reg + ")\n" +
                  "popq " + extra_reg + "\n" +
                  ".add_copy_canary_" +  to_string(counter) +  ":\n" +
                  "add $8,%fs:0x78\n"
                  ".copy_canary_" +  to_string(counter) +  ":\n" +
                  "xorq %fs:0x28," + ca_reg + "\n";
      counter++;
    }
    else
      LOG("not enough arguments for canary prologue instrumentation: "<<args);
  }
  else if(h == InstPoint::SHSTK_CANARY_MOVE) {
    inst_code = inst_code + 
                "mov %fs:0x28," + args + "\n"; 
  }
  else if(h == InstPoint::SHSTK_CANARY_EPILOGUE) {
    inst_code = inst_code + 
                "xorq %fs:0x28," + args + "\n" +
                "movq " + args + ",%fs:0x78\n" +
                "xor " + args + "," + args + "\n";
  }
  else if(h == InstPoint::SYSCALL_CHECK) {
    inst_code += save();
    inst_code += args + "call .SYSCHK\n";
    inst_code = inst_code + restore();
  }

  return inst_code;

}

string
Instrument::generate_hook(string hook_target, string args,
                          string mne,
                          InstPoint p,
                          HookType h,
                          string fall_sym,
                          uint64_t sigaction_addrs) {

  /* Generates assembly code stub to be put at the instrumentation point
   *(basic block or function).
   *  The stub saves caller saved registers and flags.
   *  Then makes a call to the instrumentation code.
   */

  string inst_code = "";

  if(h != HookType::PREDEF_INST && h != HookType::INLINE_INST) {
    inst_code += save();
    inst_code += args + "call ." + hook_target + "\n";
  }

  inst_code += predefInstCode(p, mne, fall_sym, hook_target, args);

  if(h == HookType::SEGFAULT) {
    /* If the stub is supposed to install seg-fault handler, we need to make
     * an additional call to sigaction system call.
     */
    inst_code = inst_code + "mov $11, %rdi\n" +
                            "mov %rax,%rsi\n" +
                            "mov $0, %rdx\n" +
                            "call ." + to_string(sigaction_addrs) + "_" + to_string(sigaction_addrs) + "_def_code\n";
  }
  if(h != HookType::PREDEF_INST && h != HookType::INLINE_INST)
    inst_code = inst_code + restore();
  return inst_code;
}

string
Instrument::save() {
  string ins = "";
/*
  vector <string> reg_list;
  if(h == HookType::ADDRS_TRANS)
    reg_list = atfSavedReg_;
  //else if(h == HookType::SYSCALL_CHECK)
  //  reg_list = syscallCheckSavedReg_;
  else
    reg_list = savedReg_;

*/
  auto reg_list = savedReg_;
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
Instrument::restore() {
  string ins = "";
  /*
  vector <string> reg_list;
  if(h == HookType::ADDRS_TRANS)
    reg_list = atfSavedReg_;
  //else if(h == HookType::SYSCALL_CHECK)
  //  reg_list = syscallCheckSavedReg_;
  else
    reg_list = savedReg_;
  */

  auto reg_list = savedReg_;

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
Instrument::getRegVal(string reg, InstPoint h) {
  vector <string> reg_list;
  if(h == InstPoint::ADDRS_TRANS)
    return reg;
  else
    reg_list = savedReg_;
  string val = "";
  int offt = 8 * (reg_list.size() - 1);
  if(reg == "%rsp") {
    val += to_string(offt) + "(%rsp)";
    return val;
  }
  else if (reg.find ("rsp") != string::npos) {
    DEF_LOG("Getting reg val: "<<reg);
    int pos = reg.find ("(");
    if(pos == string::npos)
      return val;
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
