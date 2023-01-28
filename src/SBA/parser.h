/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef PARSER_H
#define PARSER_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class RTL;
   /* ------------------------------- Parser -------------------------------- */
   class Parser {
    public:
      Parser() {};
      static RTL* process(const string& _s);
   };
}

#endif
