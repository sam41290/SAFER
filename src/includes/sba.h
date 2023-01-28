/*
      Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems
         Lab, Stony Brook University, Stony Brook, NY 11794.
         */

#ifndef SBA_H
#define SBA_H

#include <string>
#include <vector>
#include <unordered_map>
#include "../SBA/user.h"
#include "../SBA/jtable.h"

namespace sba {
   void setup(const std::string& autoFile);
   bool load_program(const std::string& asmFile,
             const std::unordered_map<int64_t,int64_t>& insnSize,
             const std::unordered_map<int64_t, std::vector<int64_t>>& jumpTable,
             const std::vector<int64_t>& entry);
   bool analyse(int func_index);
   void print_stats();
   ANALYSIS_HDR
}

#endif
