/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef PARSER_H
#define PARSER_H

#include "common.h"
// -----------------------------------------------------------------------------
class RTL;
// -----------------------------------------------------------------------------
class Parser {
 public:
   Parser() {};
   static RTL* process(const string& _s);
};

#endif