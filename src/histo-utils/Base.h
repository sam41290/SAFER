#ifndef BASE_H
#define BASE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <algorithm>
#include <climits>

extern int logLevel;

#define DEBUGLEVEL 5
#define INFOLEVEL  4
#define WARNLEVEL  3
#define ERRLEVEL   2

#define errMsg(x) do { if (logLevel >= ERRLEVEL) { x; }} while(0);
#define warnMsg(x) do { if (logLevel >= WARNLEVEL) { x; }} while(0); 
#define infoMsg(x) do { if (logLevel >= INFOLEVEL) { x; }} while(0); 
#define dbgMsg(x) do { if (logLevel >= DEBUGLEVEL) { x; }} while(0); 

#ifdef TESTING
#define assert_try(x) assert(x)
#define assert_fix(x, y) assert(x)
#define assert_abort(x) assert(x)
#else
#undef assert
#define assert(x) static_assert(0==1, "Assert disabled, use assert_fix, assert_abort, or other variants");
#define assert_try(cond) do {\
   if (!(cond)) \
      errMsg(std::cerr << "***** " << __FILE__ << ":" << __LINE__ << \
             ": Assertion " << #cond << " violated, attempting to continue\n");\
} while (0)

#define assert_fix(cond, fix) do {\
   if (!(cond)) {\
      errMsg(std::cerr << "***** " << __FILE__ << ":" << __LINE__ \
             << ": Assertion " << #cond << " violated, correcting action: " \
             << #fix << '\n'); \
      do { fix; } while (0); \
   }\
} while (0)

#define assert_abort(expr) \
   ((expr)                                      \
   ? __ASSERT_VOID_CAST (0)						\
   : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))
#endif

#define getbf(x, n) (x & (1ul<<(n)))
#define setbf(x, n, i) x = ((x) & (~(1ul<<(n)))) | ((i) << (n))
#define getbfs(x, n, m) (((x) & ((m)<<(n))) >> (n))
#define setbfs(x, n, i, m) x = (x & (~((m)<<(n))))|((i&m)<<(n))
#define mask(n) ((1ul<<(n))-1)

inline constexpr unsigned nbits(unsigned l) { 
   return 32 - (l > 0? __builtin_clz(l) : 32); 
};
inline constexpr unsigned nbits(unsigned long l) { 
   return 64 - (l > 0? __builtin_clzl(l) : 64);
};

inline constexpr int ilog2(unsigned l) { 
   return (l > 0? 31 - __builtin_clz(l) : INT_MIN); 
};
inline constexpr int ilog2(unsigned long l) { 
   return (l > 0? 63 - __builtin_clzl(l) : INT_MIN);
};

#define cmax(x,y) (((x) >= (y))? (x) : (y))

using namespace std;
#endif
