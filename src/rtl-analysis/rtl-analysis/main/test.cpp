/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include "../../includes/libanalysis.h"
#include "../../../run/config.h"

using namespace std;
using namespace analysis;

int main(int argc, char **argv) {
   /* load automaton */
   setup(TOOL_PATH"auto/output.auto");

   string s;
   vector<int64_t> validEntry;
   fstream f(string(argv[1]), fstream::in);

   while (getline(f,s)) {
      vector<int64_t> entryList;
      cout << "--------------------------------------" << endl;
      cout << "processing " << s << endl;

      /* get entry */
      auto entryStr = s.substr(s.find_last_of("/")+1, 7);
      auto entry = stoll(entryStr, nullptr, 10);

      /* get insn size */
      unordered_map<int64_t,int64_t> insnSize;
      {
         string s2;
         fstream g(s + "_0.sz");
         while (getline(g, s2)) {
            stringstream ss;
            int64_t offset;
            int sz;
            ss << s2;
            ss >> offset >> sz;
            insnSize[offset] = sz;
         }
         g.close();
      }
      // {
      //    string s2;
      //    int64_t prev_offset;
      //    fstream g(s + "_0.s");
      //    while (getline(g, s2)) {
      //       stringstream ss;
      //       char c;
      //       int64_t offset;
      //       ss << s2;
      //       ss >> c >> offset;
      //       insnSize[prev_offset] = offset-prev_offset;
      //       prev_offset = offset;
      //    }
      //    insnSize[prev_offset] = 4;
      //    g.close();
      // }

      /* get indirect targets */
      unordered_map<int64_t, vector<int64_t>> table;
      {
         string s2;
         fstream g(s + ".ind");
         while (getline(g, s2)) {
            stringstream ss;
            int64_t offset;
            int64_t tmp;
            vector<int64_t> vec;
            auto pos = s2.find(":");
            s2.erase(pos, 1);
            ss << s2;
            ss >> offset;
            while (ss >> tmp)
               vec.push_back(tmp);
            table[offset] = vec;
         }
         g.close();
      }

      /* load program */
      set_init(4);
      entryList.push_back(entry);
      bool valid_prog = load(s + "_0.s", insnSize, table, entryList);
      if (valid_prog) {
         /* analyze one function at a time */
         for (int func_index = 0; ; ++func_index) {
            bool valid_func = analyze(func_index);
            if (valid_func) {
               valid_func &= (uninit() == 0);
               valid_func &= preserved(vector<string>{"sp","bx","bp","r12","r13","r14","r15"});
               first_used_redef();
               auto jumpTable = jump_table_analysis();
               if (valid_func)
                  validEntry.push_back(entryList.at(func_index));
            }
            else
               break;
         }
      }
   }

   f.close();

   for (auto x: validEntry)
      std::cout << "valid entry: " << x << "\n";

   print_stats();

   return 0;
}