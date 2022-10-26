/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "arch.h"
// -----------------------------------------------------------------------------
std::string X86_64::to_string(REG reg)  {
   return X86_64::REG_STR[(int)reg];
}


X86_64::REG X86_64::from_string(const std::string &reg) {
   for (int i = 0; i < NUM_REG; ++i)
      if (!reg.compare(X86_64::REG_STR[i]))
         return (REG)i;
   return REG::UNKNOWN;
}