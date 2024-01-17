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
  DEF_LOG("Registering instrumentation: "<<(int)p<<" "<<func_name);
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
Instrument::directCallShstkTramp() {
  string inst_code = "";
  static int counter;
  //if(alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK)) {
    inst_code += "endbr64\n";
    inst_code += "cmpq $0,%fs:0x78\n";
    inst_code += "jne .push_ra_" + to_string(counter) + "\n";
    inst_code += "callq .init_shstk\n";
    inst_code += ".push_ra_" + to_string(counter) + ":\n";
    inst_code += "mov %fs:0x78,%r11\n";
    inst_code += "mov 0(%rsp),%r10\n";
    inst_code += "mov %r10,(%r11)\n";
    inst_code += "addq $8,%fs:0x78\n";
    counter++;
    return inst_code;
  //}
  //else if(alreadyInstrumented(InstPoint::SHADOW_STACK)) {
  //  inst_code += "cmpq $0,%fs:0x78\n";
  //  inst_code += "jne .push_ra_" + to_string(counter) + "\n";
  //  inst_code += "callq .init_shstk\n";
  //  inst_code += ".push_ra_" + to_string(counter) + ":\n";
  //  inst_code += "mov (%rsp), %r10\n";
  //  inst_code += "movq %fs:0x78,%r11\n";
  //  inst_code += "movq %r10,(%r11)\n";
  //  counter++;
  //  return inst_code;
  //}
  //return inst_code;
}

string
Instrument::generate_hook(string hook_target, string args,
                          string mne,
                          HookType h,
                          string fall_sym,
                          uint64_t sigaction_addrs) {

  /* Generates assembly code stub to be put at the instrumentation point
   *(basic block or function).
   *  The stub saves caller saved registers and flags.
   *  Then makes a call to the instrumentation code.
   */
  static int counter;
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
  else if(h == HookType::LEGACY_SHADOW_CALL) {
    inst_code += "call " + hook_target + "\n";
    inst_code += fall_sym + ":\n";
    //inst_code += "jmp " + hook_target + "\n";
    //inst_code += ".shadow_inst_" + to_string(counter) + ":\n";
    //inst_code += "cmpq $0,%fs:0x78\n";
    //inst_code += "jne .push_ra_" + to_string(counter) + "\n";
    //inst_code += "callq .init_shstk\n";
    //inst_code += ".push_ra_" + to_string(counter) + ":\n";
    //inst_code += "addq $16,%fs:0x78\n";
    //inst_code += "mov %rax,%fs:0x88\n";
    //inst_code += "mov %fs:0x78,%rax\n";
    //inst_code += "push %rbx\n";
    //inst_code += "mov 8(%rsp),%rbx\n";
    //inst_code += "mov %rbx,-8(%rax)\n";
    //inst_code += "pop %rbx\n";
    //inst_code += "mov %rsp,-16(%rax)\n";
    //inst_code += "mov %fs:0x88,%rax\n";
    //counter++;
  }
  else if(h == HookType::LEGACY_SHADOW_INDRCT_CALL) {
      //inst_code += "mov %rax,%fs:0x88\n";
      //string op = hook_target;
      //op.replace(0,1,"");
      //inst_code += "mov " + op + ",%rax\n";
      //inst_code += "call .shadow_tramp\n"; 
      //inst_code += fall_sym + ":\n";
  }
  else if(h ==  HookType::LEGACY_SHADOW_RET) {
    inst_code = inst_code + 
                ".rep_pop_" + to_string(counter) + ":\n" +
                "sub $8, %fs:0x78\n" +
                "mov %fs:0x78,%r11\n" +
                "mov (%rsp),%r10\n" +
                "mov (%r11),%r11\n" +
                "xor %r11,%r10\n" +
                "jne .rep_pop_" + to_string(counter) + "\n" +
                "ret\n";

    //inst_code += "cmpq $0,%fs:0x78\n";
    //inst_code += "jg .legacy_shadow_chk_" + to_string(counter) + "\n";
    //inst_code += "ret\n";
    //inst_code += ".legacy_shadow_chk_" + to_string(counter) + ":\n";
    //inst_code += "push %rdx\n";
    //inst_code += "mov %rax,%fs:0x88\n";
    //inst_code += "mov 8(%rsp),%rdx\n"; 
    //inst_code += "lea .loader_map_start(%rip),%rax\n"; 
    //inst_code += "cmp (%rax),%rdx\n";
    //inst_code += "jl  .ra_chk_" + to_string(counter) + "\n";
    //inst_code += "lea .loader_map_end(%rip),%rax\n" ;
    //inst_code += "cmp (%rax),%rdx\n";
    //inst_code += "jl  .ret_post_chk_" + to_string(counter) + "\n";
    //inst_code += ".ra_chk_" + to_string(counter) + ":\n";
    //inst_code += "mov %fs:0x78,%rax\n";
    //inst_code += "mov %rsp,%rdx\n";
    //inst_code += "add $8,%rdx\n";
    //inst_code += ".ra_chk_loop_" + to_string(counter) + ":\n";
    //inst_code += "cmp %rax,%fs:0x80\n";
    //inst_code += "je .ret_post_chk_" + to_string(counter) + "\n";
    //inst_code += "sub $16,%rax\n";
    //inst_code += "mov %rax,%fs:0x78\n";
    //inst_code += "cmp 0(%rax),%rdx\n";
    //inst_code += "jne .ra_chk_loop_" + to_string(counter) + "\n"; 
    //inst_code += "mov 8(%rsp),%rdx\n"; 
    //inst_code += "cmp 8(%rax),%rdx\n";
    //inst_code += "je .ret_post_chk_" + to_string(counter) + "\n"; 
    //inst_code += "nop\n";
    //inst_code += ".ret_post_chk_" + to_string(counter) + ":\n";
    //inst_code += "pop %rdx\nmov %fs:0x88,%rax\nret\n";
    counter++;
  }
  else if(h == HookType::RET_CHK) {
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
      inst_code += decodeRet(hook_target,args,mne);
      DEF_LOG("Return check code: "<<inst_code);
    }
  }
  //else if (h == HookType::SHSTK_FUNCTION_CALL) {
  //  inst_code = inst_code + 
  //               "pushq %rdi\n" +
  //               "pushq %rax\n" +
  //               "cmpq $0,%fs:0x78\n" +
  //               "jne .shstk_ok_" + to_string(counter) + "\n" +
  //               "callq .init_shstk\n"
  //               ".shstk_ok_" + to_string(counter) +  ":\n" +
  //               "movq %fs:0x78,%rax\n" +
  //               "lea " + args + "(%rip),%rdi\n" +
  //               "movq %rdi,(%rax)\n" +
  //               "pop %rax\n" +
  //               "pop %rdi\n";
  //  //counter++;
  //}
  //else if(h == HookType::SHSTK_DRCT_CALL) {
  //  inst_code += "call " + hook_target + "\n";
  //  inst_code += fall_sym + ":\n";
  //}
  //else if(h == HookType::SHSTK_INDRCT_CALL) {
  //    inst_code += "mov %rax,%fs:0x88\n";
  //    string op = hook_target;
  //    op.replace(0,1,"");
  //    inst_code += "mov " + op + ",%rax\n";
  //    inst_code += "call .shadow_tramp\n"; 
  //    inst_code += fall_sym + ":\n";
  //}
  else if (h == HookType::SHSTK_FUNCTION_RET) {
    inst_code = inst_code + 
                "mov %fs:0x78,%r11\n" +
                "mov (%r11),%r11\n" +
                "mov %r11,(%rsp)\n";
                //"movq (%rsp),%r10\n" +
                //"mov %fs:0x78,%r11\n" +
                //"cmpq (%r11),%r10\n" + args + "\n" +
                //"jne .safe_ret_" + to_string(counter) + "\n" +
                //"ret\n" +
                //".safe_ret_" + to_string(counter) + ":\n" +
                //"hlt\n";
    counter++;
  }
  else if(h == HookType::SHSTK_FUNCTION_ENTRY) {
    inst_code = inst_code +
                //"mov %fs:0x78, %r11\n"
                //"cmpq $0,%r11\n" +
                //"jg .shstk_ok_" + to_string(counter) + "\n" +
                //".init_sh_" + to_string(counter) +  ":\n" +
                //"callq .init_shstk\n" +
                "mov %fs:0x78, %r11\n"
                ".shstk_ok_" + to_string(counter) +  ":\n" +
                "mov (%rsp), %r10\n" +
                "movq %r10,(%r11)\n";
    counter++;
  }
  else if(h == HookType::SHSTK_CANARY_CHANGE) {
    string ca_reg = args;
    inst_code = inst_code + 
                "movq %fs:0x78," + ca_reg + "\n" +
                //"add $8," + ca_reg + "\n" +
                //"movq " + ca_reg + ",%fs:0x78\n" +
                //"addq $8,%fs:0x78\n" +
                "xorq %fs:0x28," + ca_reg + "\n";
  }
  else if(h == HookType::SHSTK_CANARY_PROLOGUE) {
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

    //ca_reg = args.substr(0, args.find(","));
    //ra_offt = args.substr(args.find(",") + 1);
    //string extra_reg = "%r10";
    //if(ca_reg.find("r10") != string::npos) {
    //  extra_reg = "%r9";
    //}
    //inst_code = inst_code + 
    //            "cmpq $0,%fs:0x78\n" +
    //            "jg .shstk_ok_" + to_string(counter) + "\n" +
    //            ".init_sh_" + to_string(counter) +  ":\n" +
    //            "callq .init_shstk\n" +
    //            ".shstk_ok_" + to_string(counter) +  ":\n" +
    //            "movq %fs:0x78," + ca_reg + "\n" +
    //            "addq $8,%fs:0x78\n" +
    //            "pushq " + extra_reg + "\n" +
    //            "movq " + ra_offt + "," + extra_reg + "\n" +
    //            "movq " + extra_reg + ",(" + ca_reg + ")\n" +
    //            "xorq %fs:0x28," + ca_reg + "\n" +
    //            "popq " + extra_reg + "\n";
    //counter++;
  }
  else if(h == HookType::SHSTK_CANARY_MOVE) {
    inst_code = inst_code + 
                "mov %fs:0x28," + args + "\n"; 
  }
  else if(h == HookType::SHSTK_CANARY_EPILOGUE) {
    inst_code = inst_code + 
                "xorq %fs:0x28," + args + "\n" +
                //"je .canary_ok_" + to_string(counter) + "\n" +
                "sub $8," + args + "\n" + 
                "movq " + args + ",%fs:0x78\n" +
                "xor " + args + "," + args + "\n";
                //".canary_ok_" + to_string(counter) + ":\n";
    //counter++;
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
     && h != HookType::SHSTK_CANARY_EPILOGUE
     && h != HookType::SHSTK_CANARY_PROLOGUE
     && h != HookType::SHSTK_CANARY_MOVE
     && h != HookType::SHSTK_CANARY_CHANGE
     //&& h != HookType::SHSTK_DRCT_CALL
     //&& h != HookType::SHSTK_INDRCT_CALL
     && h != HookType::SHSTK_FUNCTION_RET
     && h != HookType::SHSTK_FUNCTION_ENTRY
     && h != HookType::LEGACY_SHADOW_CALL
     && h != HookType::LEGACY_SHADOW_RET
     && h != HookType::LEGACY_SHADOW_INDRCT_CALL)
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
