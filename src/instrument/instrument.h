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
  LEA_INS_POST
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



class Instrument
{
  bool decode = false;
  bool encode = false;
  vector<pair<InstPoint,string>> targetPos_;
  map<string,vector<InstArg>>instArgs_;
  vector<pair<string,string>> targetFuncs_;
  vector<pair<uint64_t,string>> targetAddrs_;
  vector<string> instFuncs_;
  string exeNameLabel_ = ".exename";
public:
  Instrument(){}
  vector<pair<InstPoint,string>> targetPositions() { return targetPos_;}
  vector<pair<string,string>> targetFunctions() { return targetFuncs_;}
  vector<string> instFunctions() { return instFuncs_;}
  string exeNameLabel() { return exeNameLabel_; };
  map<string,vector<InstArg>> instArgs() { return instArgs_; }
  vector<pair<uint64_t,string>> targetAddrs() { return targetAddrs_; }
  


  void decode_icf_target (string file_name, string mnemonic, string op1,
			  uint64_t loc);
  void encode_lea_instruction (string file_name, string mnemonic, string op1,
      uint64_t loc);
  void set_encode (bool to_encode);
  bool get_encode ();
  void set_decode (bool to_decode);
  bool get_decode ();
  
  string moveZeros(string op1,uint64_t loc, string file_name);
  string getIcfReg(string op1);
  
  void registerInstrumentation(uint64_t tgtAddrs,string
      instCodeSymbol,vector<InstArg>argsLst);
  void registerInstrumentation(InstPoint p,string
      instCodeSymbol,vector<InstArg>argsLst);
  void registerInstrumentation(string fnName,string
      instCodeSymbol,vector<InstArg>argsLst);

  string generate_hook(string hook_target, bool is_segfault_hook, uint64_t
      sigaction_addrs, string args);
  string getRegVal(string reg);  
  virtual void instrument() = 0;

private:
  string save();
  string restore();
};
