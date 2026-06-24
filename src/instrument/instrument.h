#pragma once
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include <regex>
#include <map>
#include "Pointer.h"

/* class instrument provides interface to add additional instrumentation code at
 * given instrumentation points.
 *
 * class is inheritted by class instruction and class basic_block.
 */

using namespace std;

#define INSTARGCNT 22

enum class InstPos {
  PRE,
  POST
};

enum class InstPoint
{
  BASIC_BLOCK,
  INSTRUCTION,
  FUNCTION_ENTRY,
  SYSCALL,
  CALL,
  RET,
  INDIRECT_CF,
  CUSTOM,  
  //Predefined instrumentations
  RET_CHK, //Return address translation 
  SHADOW_STACK, //canary based shadow stack
  LEGACY_SHADOW_STACK, //Traditional shadow stack
  LEGACY_SHADOW_CALL,
  LEGACY_SHADOW_RET,
  SHSTK_CANARY_PROLOGUE,
  SHSTK_CANARY_MOVE,
  SHSTK_CANARY_EPILOGUE,
  SHSTK_CANARY_RET_CHK,
  SHSTK_IGNORE_RET,
  //SHSTK_FUNCTION_CALL,
  SHSTK_FUNCTION_RET,
  SHSTK_CANARY_CHANGE,
  SHSTK_FUNCTION_ENTRY,
  SHSTK_FUNCTION_TRAMP,
  SHSTK_FUNCTION_PTR,
  SHSTK_TAIL_CALL,
  SHSTK_IGNORE_TAIL_CALL,
  ADDRS_TRANS, //Address translation and pointer decoding 
  SYSCALL_CHECK //Translate pointers passed as arguments to syscalls
};

enum class HookType
{
  SEGFAULT,
  PREDEF_INST,
  INLINE_INST,
  CALL_BASED_INST
};


enum class InstArg {
  NONE = 0,
  RIP,
  INDIRECT_TARGET,
  LEA_VAL,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
  REG_RDI,
  REG_RSI,
  REG_RBP,
  REG_RBX,
  REG_RDX,
  REG_RAX,
  REG_RCX,
  REG_RSP,
  EXENAME,
  //EFLAGS, //Need to add implementation in cfg/Instrument.cpp's setInsParams()
  CUSTOM_DATA0,
  CUSTOM_DATA1,
  CUSTOM_DATA2,
  CUSTOM_DATA3,
  CUSTOM_DATA4
};

struct InstUnit {
  HookType instType_;
  InstPos pos_;
  string instCode_;
  vector<InstArg> args_;
};

struct InstData {
  string symbol_ = "";
  void *data_ = NULL;
  int size_ = 0;
};


class Instrument: public ENCCLASS
{
  vector<pair<InstPoint,InstUnit>> targetPos_;
  vector<pair<string,InstUnit>> targetFuncs_;
  static vector<string> instFuncs_;
  static map<int, InstData *> instDataMap_;
  string exeNameLabel_ = ".exename";
  static int counter;
public:
  Instrument(){}
  void removeInstrumentation(InstPoint p) {
    for(auto it = targetPos_.begin(); it != targetPos_.end(); it++) {
      if((*it).first == p) {
        targetPos_.erase(it);
        break;
      }
    }
  }
  bool alreadyInstrumented(InstPoint p) {
    for(auto it = targetPos_.begin(); it != targetPos_.end(); it++) {
      if((*it).first == p) {
        return true;
      }
    }
    return false;
  }
  vector<pair<InstPoint,InstUnit>> targetPositions() { return targetPos_;}
  vector<pair<string, InstUnit>> targetFunctions() { return targetFuncs_;}
  vector<string> instFunctions() { return instFuncs_;}
  map<int, InstData *> instDataMap() { return instDataMap_; }
  string exeNameLabel() { return exeNameLabel_; };
  //map<string,vector<InstArg>> instArgs() { return instArgs_; }
  //ector<pair<uint64_t,string>> targetAddrs() { return targetAddrs_; }
  string moveZeros(string op1,uint64_t loc, string file_name);
  string getIcfReg(string op1);
  void registerInstrumentation(InstPoint p, InstUnit &u);
  void registerInstrumentation(InstPoint p,InstPos pos, string instCodeSymbol);
  void registerInstrumentation(InstPoint p,InstPos pos, string instCodeSymbol,
                               vector<InstArg> argsLst);
  void registerInstrumentation(string fnName,string instCodeSymbol,
                               vector<InstArg>argsLst);
  void registerInlineInstrumentation(string asm_str,InstPos p, InstPoint pnt); 
  void registerInlineInstrumentation(string asm_str,InstPos p); 
  void registerInbuiltInstrumentation(InstPoint p);
  string generate_hook(string hook_target, string args = "",
                       string mne = "",
                       InstPoint p = InstPoint::CUSTOM,
                       HookType h = HookType::CALL_BASED_INST,
                       string fall = "",
                       uint64_t sigaction_addrs = 0);
  string getRegVal(string reg, InstPoint h);  
  string directCallShstkTramp();
  string shadowRetInst(string &reg1, string &reg2, int free_reg_cnt);
  InstArg addInstrumentationData(void *data, int size);
  virtual void instrument() = 0;

private:
  string save();
  string restore();
  string predefInstCode(InstPoint h, string mne, string fall_sym, 
                        string hook_target, string args);
};
