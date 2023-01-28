/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef USER_H
#define USER_H

#include "default.h"

// #define CUSTOM_DOMAIN
// #define CUSTOM_RTL


#ifndef CUSTOM_DOMAIN
   #define DOMAIN_HDR
   #define DOMAIN_VAR
   #define DOMAIN_CPP
   #define STATE_EXTERN             DEFAULT_STATE_EXTERN
   #define STATE_INSTANT            DEFAULT_STATE_INSTANT
   #define FLAG_UNIT_EXTERN         DEFAULT_FLAG_UNIT_EXTERN
   #define FLAG_UNIT_INSTANT        DEFAULT_FLAG_UNIT_INSTANT
   #define FLAG_DOMAIN_EXTERN       DEFAULT_FLAG_DOMAIN_EXTERN
   #define FLAG_DOMAIN_INSTANT      DEFAULT_FLAG_DOMAIN_INSTANT
   #define CSTR_DOMAIN_EXTERN       DEFAULT_CSTR_DOMAIN_EXTERN
   #define CSTR_DOMAIN_INSTANT      DEFAULT_CSTR_DOMAIN_INSTANT
   #define EXPR_VAL_INSTANT         DEFAULT_EXPR_VAL_INSTANT
   #define EXPR_VAL_CPP             DEFAULT_EXPR_VAL_CPP
#else
   #include "user_domain.h"
#endif


#ifndef CUSTOM_RTL
   #define EXECUTE_ASSIGN(states)   DEFAULT_EXECUTE_ASSIGN(states)
   #define EXECUTE_CALL(states)     DEFAULT_EXECUTE_CALL(states)
   #define EXECUTE_EXIT(states)     DEFAULT_EXECUTE_EXIT(states)
   #define EVAL_CONST(states)       DEFAULT_EVAL_CONST(states)
   #define EVAL_REGISTER(states)    DEFAULT_EVAL_REGISTER(states)
   #define EVAL_MEMORY(states)      DEFAULT_EVAL_MEMORY(states)
   #define EVAL_SUBREG(states)      DEFAULT_EVAL_SUBREG(states)
   #define EVAL_IFELSE(states)      DEFAULT_EVAL_IFELSE(states)
   #define EVAL_CONVERSION(states)  DEFAULT_EVAL_CONVERSION(states)
   #define EVAL_NOTYPE(states)      DEFAULT_EVAL_NOTYPE(states)
   #define EVAL_UNARY(states)       DEFAULT_EVAL_UNARY(states)
   #define EVAL_BINARY(states)      DEFAULT_EVAL_BINARY(states)
   #define EVAL_COMPARE(states)     DEFAULT_EVAL_COMPARE(states)
#else
   #include "user_rtl.h"
#endif

#endif
