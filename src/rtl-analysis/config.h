/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef CONFIG_H
#define CONFIG_H

/* framework settings */
#define ARCH X86_64
#define domainCnt 3
#define debugLevel 2
      /* 0: off              */
      /* 1: critical errors  */
      /* 2: output           */
      /* 3: debug info       */
      /* 4: extra debug info */
#define max_domain_length 10
#define timeStat true

/* enable flags to safely abort when processing erroneous input */
#define flag_unlifted_insn                false

/* abstract state settings */
#define rangeLimit      100
#define  oo             9223372036854775807LL
#define _oo             (-9223372036854775807LL-1LL)
#define norm_max        1000000000
#define norm_min        (-1000000000)
#define CSTR_CNT_LIMIT  10
#define boundRange(r,i) ((int64_t)((int)r==0? (i==0?     1: ARCH::NUM_REG-1): \
                                  ((int)r==1? (i==0? -5000: 80 ): \
                                              (i==0?     0: 100))))
#define boundSize(r)    (boundRange(r,1) - boundRange(r,0) + 1)
#define baseRegion(r)   ((int64_t)((int)r==1? ARCH::NUM_REG: \
                        ARCH::NUM_REG+boundSize(REGION::STACK)+1))

/* template instantiation */
#define EXTERN_FLAG_UNIT     extern template class FlagUnit<BaseLH>; \
                             extern template class FlagUnit<InitDomain>;
#define EXTERN_FLAG_DOMAIN   extern template class FlagDomain<BaseLH>; \
                             extern template class FlagDomain<InitDomain>;
#define EXTERN_CSTR_DOMAIN   extern template class CstrDomain<BaseLH>; \
                             extern template class CstrDomain<InitDomain>;
#define EXTERN_ABS_STATE     extern template class AbsState<BaseLH>; \
                             extern template class AbsState<InitDomain>;
#define INSTANTIATE_COMPARE_ARGS    template class CompareArgsVal<BaseLH>; \
                                    template class CompareArgsVal<InitDomain>;
#define INSTANTIATE_FLAG_UNIT       template class FlagUnit<BaseLH>; \
                                    template class FlagUnit<InitDomain>;
#define INSTANTIATE_FLAG_DOMAIN     template class FlagDomain<BaseLH>; \
                                    template class FlagDomain<InitDomain>;
#define INSTANTIATE_CSTR_DOMAIN     template class CstrDomain<BaseLH>; \
                                    template class CstrDomain<InitDomain>;
#define INSTANTIATE_ABS_STATE       template class AbsState<BaseLH>; \
                                    template class AbsState<InitDomain>;

#endif