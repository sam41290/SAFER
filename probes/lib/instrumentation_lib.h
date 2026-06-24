/*-----------------------------------------------------------------------

Author: Sousaferakant Priyadarshan
		PhD student, Stony Brook University

Description:
	Contains declarations of library functions to be used while building instrumentation code.
	
*------------------------------------------------------------------------*/



#ifndef _INSTRUMENT_LIB_H
#define _INSTRUMENT_LIB_H

#include <stdarg.h>
#include <stdint.h>
#include <ucontext.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdlib.h>
enum
{
  REG_R8 = 0,
#define REG_R8     REG_R8
  REG_R9,
#define REG_R9     REG_R9
  REG_R10,
#define REG_R10    REG_R10
  REG_R11,
#define REG_R11    REG_R11
  REG_R12,
#define REG_R12    REG_R12
  REG_R13,
#define REG_R13    REG_R13
  REG_R14,
#define REG_R14    REG_R14
  REG_R15,
#define REG_R15    REG_R15
  REG_RDI,
#define REG_RDI    REG_RDI
  REG_RSI,
#define REG_RSI    REG_RSI
  REG_RBP,
#define REG_RBP    REG_RBP
  REG_RBX,
#define REG_RBX    REG_RBX
  REG_RDX,
#define REG_RDX    REG_RDX
  REG_RAX,
#define REG_RAX    REG_RAX
  REG_RCX,
#define REG_RCX    REG_RCX
  REG_RSP,
#define REG_RSP    REG_RSP
  REG_RIP,
#define REG_RIP    REG_RIP
  REG_EFL,
#define REG_EFL    REG_EFL
  REG_CSGSFS,			/* Actually short cs, gs, fs, __pad0.  */
#define REG_CSGSFS REG_CSGSFS
  REG_ERR,
#define REG_ERR    REG_ERR
  REG_TRAPNO,
#define REG_TRAPNO REG_TRAPNO
  REG_OLDMASK,
#define REG_OLDMASK    REG_OLDMASK
  REG_CR2
#define REG_CR2    REG_CR2
};

/* Convenience macros */

long sys_call(unsigned long n,
		            unsigned long a1, unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5, unsigned long a6);

#define sys_call0(n)                 sys_call((n),0,0,0,0,0,0)
#define sys_call1(n,a1)              sys_call((n),(a1),0,0,0,0,0)
#define sys_call2(n,a1,a2)           sys_call((n),(a1),(a2),0,0,0,0)
#define sys_call3(n,a1,a2,a3)        sys_call((n),(a1),(a2),(a3),0,0,0)
#define sys_call4(n,a1,a2,a3,a4)     sys_call((n),(a1),(a2),(a3),(a4),0,0)
#define sys_call5(n,a1,a2,a3,a4,a5)  sys_call((n),(a1),(a2),(a3),(a4),(a5),0)
#define sys_call6(n,a1,a2,a3,a4,a5,a6) sys_call((n),(a1),(a2),(a3),(a4),(a5),(a6))

typedef struct gpr
{
  unsigned long r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax;	// Pushed by pushq i.e. all general purpose registers
  unsigned long rip, cs, eflags, usersp, ss;	// Pushed by the processor automatically.
} gpr_t;

int saferprintf (const char *fmt, ...);
void safer_exit();
int safer_putchar (int c);
int safer_puts (const char *s);
int printfflushint (int text, int ctr, char *args);
int printfflushhex (uint64_t num, int ctr, char *args);
void safermemset (void *p, uint8_t c, int bytes);
int safersigaction (int sig, const struct sigaction *act, struct sigaction *oact);
void *safermmap (uint64_t size);
void sa_restorer();
void safer_write(char *file, char *msg, int len);
int safer_openat(char *file, int flag, unsigned int mode);
#endif
