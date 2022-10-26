/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "util.h"

// -----------------------------------------------------------------------------
bool enable_weak_update;
bool enable_range_union;
bool enable_invalid_init;
// -----------------------------------------------------------------------------
string UnitId::to_string() {
   switch (r_) {
      case REGION::REG:
         return idx_ == -1? "invalid" : ARCH::to_string((ARCH::REG)idx_);
      case REGION::STACK:
         if (idx_ == -1000000000)
            return string("stack[out_bound]");
         return string("stack[").append(std::to_string(idx_)).append("]");
      case REGION::STATIC:
         if (idx_ == -1000000000)
            return string("static[out_bound]");
         return string("static[").append(std::to_string(idx_)).append("]");
      default:
         return string("_");
   }
}
// ---------------------------------- Util ------------------------------------
int64_t Util::to_int(const string& s) {
   string s2 = s;
   if (s2.substr(0,2).compare(".L") == 0)
      s2.erase(0,2);
   if (s2.substr(0, 2).compare("0x") == 0)
      return stoll(s2, nullptr, 16); 
   return stoll(s2, nullptr, 10);
}


double Util::to_double(const string& s) {
   return stod(s, nullptr);
}