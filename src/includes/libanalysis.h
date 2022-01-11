/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef LIBANALYSIS_H
#define LIBANALYSIS_H

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace analysis {
   struct JumpTable {
      int64_t jumpLoc = 0;
      char type = 0;
      int64_t base1 = 0;
      int64_t base2 = 0;
      char op1 = 0;
      char op2 = 0;
      int stride = 0;
   };

   bool load(const std::string& asmFile,
             const std::unordered_map<int64_t,int64_t>& insnSize,
             const std::unordered_map<int64_t,std::vector<int64_t>>& jumpTable,
             const std::vector<int64_t>& entry);
   bool load(const std::string& asmFile,
             const std::unordered_map<int64_t,int64_t>& insnSize,
             const std::vector<int64_t>& entry);
   void reset();

   bool preserved(const std::vector<std::string>& regs);
   std::unordered_set<std::string> invalid_regs();
   std::vector<JumpTable> jump_table_analysis();
}
#endif