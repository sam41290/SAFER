/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef PROGRAM_H
#define PROGRAM_H

#include "common.h"
// -----------------------------------------------------------------------------
class Function;
class BasicBlock;
class Insn;
class RTL;
// -----------------------------------------------------------------------------
class Program {
 private:
   vector<int64_t> entry_;
   unordered_map<int64_t,Insn*> insnMap_;
   unordered_map<int64_t,BasicBlock*> blockMap_;
   vector<pair<int64_t,RTL*>> pairList_;
   unordered_map<int64_t,int64_t> insnSize_;
   unordered_map<int64_t,vector<int64_t>> jumpTable_;
   int64_t index_;

 public:
   Program(const vector<pair<int64_t,RTL*>>& pairList,
           const unordered_map<int64_t,int64_t>& insnSize,
           const unordered_map<int64_t,vector<int64_t>>& jumpTable,
           const vector<int64_t>& entry, bool& corrupted);
   ~Program();   

   /* Methods related to CFG construction */
   Function* func(int index);

 private:
   /* Methods related to CFG construction */
   void load_asm(const vector<pair<int64_t,RTL*>>& pairList,
                 const unordered_map<int64_t,int64_t>& insnSize,
                 const unordered_map<int64_t,vector<int64_t>>& jumpTable,
                 bool& corrupted);
};
// -----------------------------------------------------------------------------
#endif