/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef CONFIG_H
#define CONFIG_H

/* framework settings */
#define ARCH            X86_64
#define DOMAIN_NUM      3
#define DOMAIN_LEN      10
#define PERF_STATS      1
#define DLEVEL          2        /* 0: off          */
                                 /* 1: output       */
                                 /* 2: extra output */
                                 /* 3: debug info   */
                                 /* 4: extra info   */

/* abstract state settings */
#define IMM                int32_t
#define  oo                ( 100000000)
#define _oo                (-100000000)
#define STACK_OFFSET_MAX   1000
#define STACK_OFFSET_MIN   -10000
#define STATIC_OFFSET_MAX  100000000
#define STATIC_OFFSET_MIN  0
#define APPROX_RANGE_SIZE  100
#define CSTR_LIMIT         10

/* optional settings */
#define ABORT_UNLIFTED_INSN            false
#define ABORT_INSN_CONFLICT            false
#define ABORT_MISSING_JTABLE_TARGET    false

#endif
