/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef CONST_H
#define CONST_H
#include <iostream>
#include <cstdint>
#include <stdexcept>

typedef int64_t int64;
typedef uint64_t uint64;
// ================================== RTL Expr ==================================
const char V_EXPR                      = 0;
const char V_REG                       = 1;
const char V_SUBREG                    = 2;
const char V_REF                       = 3;
const char V_MEM                       = 4;
const char V_CONST                     = 5;
const char V_IF_ELSE                   = 6;
const char V_PARALLEL                  = 7;
const char V_GENERALTYPE               = 8;
const char V_STRICT_LOW_PART           = 9;
const char V_EXTRACT                   = 10;
// ================================ CONST TYPE ==================================
const char INT_TYPE                    = 0;
const char DOUBLE_TYPE                 = 1;
// ================================ TARGET TYPE =================================
const char NO_TRANSFER                 = 0;
const char DIRECT_TARGET               = 1;
const char INDIRECT_TARGET             = 2;
// ============================= MATH EXPRESSION ================================
const int SYSTEM_ARCH_BIT              = 64;
const int SYSTEM_ARCH_BYTE             = 8;
// =============================== BASIC BLOCK ==================================
const char CHECK_TRANSFER_TYPE         = 0;
const char CHECK_TRANSFER_FULL         = 1;
// =========================== ANALYSIS INTERFACE ===============================
const char TRACK_TYPE_ENTIRE           = 0;
const char TRACK_TYPE_LAST             = 1;
// ==============================================================================
#endif