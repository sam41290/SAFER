/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef LIBANALYSIS_H
#define LIBANALYSIS_H

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include "../rtl-analysis/external.h"

namespace analysis {
   /* JTable structures */
   struct JTableBase;
   struct JTableRange;
   struct JTableAddr;
   struct JTableMem;
   struct JTableOffsetMem;
   struct JTable;

   /* Settings */
   void setup(const std::string& autoFile);
   void lifter_cache(const std::string& binFile);
   bool load(const std::string& asmFile,
             const std::unordered_map<int64_t,int64_t>& insnSize,
             const std::unordered_map<int64_t, std::vector<int64_t>>& jumpTable,
             const std::vector<int64_t>& entry);
   bool analyze(int func_index);
   void set_init(int init_option);
   void print_stats();

   /* Analysis */
   int uninit();
   int64_t first_used_redef();
   bool preserved(const std::vector<std::string>& regs);
   analysis::JTable jump_table_analysis();
}

#endif
