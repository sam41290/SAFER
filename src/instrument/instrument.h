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


enum class InstPoint
{
  BASIC_BLOCK,
  ALL_FUNCTIONS,
  INDIRECT_CF,
  LEA_INS_PRE,
  LEA_INS_POST,
  ADDRS_TRANS,
  RET_CHK,
  SYSCALL_CHECK,
  CANARY_PROLOGUE,
  CANARY_EPILOGUE,
  FUNCTION_CALL,
  FUNCTION_RET,
  LEGACY_SHADOW_STACK,
  SHADOW_STACK,
  SHSTK_CANARY_PROLOGUE,
  SHSTK_CANARY_MOVE,
  SHSTK_CANARY_EPILOGUE,
  //SHSTK_FUNCTION_CALL,
  SHSTK_FUNCTION_RET,
  SHSTK_CANARY_CHANGE,
  SHSTK_FUNCTION_ENTRY
};

enum class HookType
{
  SEGFAULT,
  ADDRS_TRANS,
  RET_CHK,
  SYSCALL_CHECK,
  GENERAL_INST,
  LEGACY_SHADOW_CALL,
  LEGACY_SHADOW_INDRCT_CALL,
  LEGACY_SHADOW_RET,
  //SHSTK_DRCT_CALL,
  //SHSTK_INDRCT_CALL,
  SHSTK_CANARY_PROLOGUE,
  SHSTK_CANARY_MOVE,
  SHSTK_CANARY_EPILOGUE,
  //SHSTK_FUNCTION_CALL,
  SHSTK_FUNCTION_RET,
  SHSTK_CANARY_CHANGE,
  SHSTK_FUNCTION_ENTRY
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
  EXENAME
};



class Instrument: public ENCCLASS
{
  vector<pair<InstPoint,string>> targetPos_;
  map<string,vector<InstArg>>instArgs_;
  vector<pair<string,string>> targetFuncs_;
  vector<pair<uint64_t,string>> targetAddrs_;
  vector<string> instFuncs_;
  string exeNameLabel_ = ".exename";
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
  vector<pair<InstPoint,string>> targetPositions() { return targetPos_;}
  vector<pair<string,string>> targetFunctions() { return targetFuncs_;}
  vector<string> instFunctions() { return instFuncs_;}
  string exeNameLabel() { return exeNameLabel_; };
  map<string,vector<InstArg>> instArgs() { return instArgs_; }
  vector<pair<uint64_t,string>> targetAddrs() { return targetAddrs_; }
  string moveZeros(string op1,uint64_t loc, string file_name);
  string getIcfReg(string op1);
  void registerInstrumentation(uint64_t tgtAddrs,string
      instCodeSymbol,vector<InstArg>argsLst);
  void registerInstrumentation(InstPoint p,string
      instCodeSymbol,vector<InstArg>argsLst);
  void registerInstrumentation(string fnName,string
      instCodeSymbol,vector<InstArg>argsLst);
  string generate_hook(string hook_target, string args = "",
                          string mne = "",
                          HookType h = HookType::GENERAL_INST,
                          string fall = "",
                          uint64_t sigaction_addrs = 0);
  string getRegVal(string reg, HookType h);  
  string directCallShstkTramp();
  virtual void instrument() = 0;

private:
  string save(HookType h);
  string restore(HookType h);
};
