#include <stdio.h>
#include <stdlib.h>

#include <ucontext.h>
#include <signal.h>
#include "instrumentation_lib.h"


__thread int global_thread_local = 0;

int
instrument_bb ()
{
  myprintf ("Hahahaha\n");
  return 0;
}

void
segfault_handler (int nSignum, siginfo_t * si, void *vcontext)
{
  ucontext_t *context = (ucontext_t *) vcontext;
  myprintf ("Segfault at RIP: %p faulting pointer: %p\n",
      context->uc_mcontext.gregs[REG_RIP],context->uc_mcontext.gregs[REG_CR2]);
  my_exit();
  //context->uc_mcontext.gregs[REG_RIP]++;
  //
  //int *ptr = mymmap (sizeof (int));
  //context->uc_mcontext.gregs[REG_CR2] = (uint64_t)ptr;
  //

  //if(context->uc_mcontext.gregs[REG_CR2] & 0xfff0000000000000 != 0)
  //{
  //  context->uc_mcontext.gregs[REG_RIP] = 
  //    context->uc_mcontext.gregs[REG_CR2] & 0x000fffffffffffff;
  //}
  //else
  //  context->uc_mcontext.gregs[REG_RIP]++;
}

void LOG(uint64_t tgt, uint64_t rip)
{
  myprintf("RIP value: %p RAX value: %p\n", rip,tgt);
}

void LOG2(char *exe, uint64_t RIP, uint64_t tgt)
{
  myprintf("::::::%s ||RIP: %p lea val: %p\n", exe,RIP,tgt);
}

void LOGRAX(char *exe, uint64_t RIP, uint64_t tgt)
{
  myprintf("::::::%s ||RIP: %p RAX val: %p\n", exe,RIP,tgt);
}

unsigned long atf(unsigned long att, unsigned long addr) {
  return 0;
}

void
install_signal ()
{
  struct sigaction action;
  mymemset ((void *) (&action), 0, sizeof (struct sigaction));
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = segfault_handler;
  //action.sa_restorer = sa_restorer;
  mysigaction (SIGSEGV, &action, NULL);
}

void
check_handler ()
{
  struct sigaction action;
  mymemset ((void *) (&action), 0, sizeof (struct sigaction));
  mysigaction (SIGSEGV, NULL, &action);
  myprintf ("Handler: %p\n", action.sa_sigaction);

}

struct sigaction *
fill_sigaction ()
{
  struct sigaction *action = mymmap (sizeof (struct sigaction));
  mymemset ((void *) (action), 0, sizeof (struct sigaction));
  action->sa_flags = SA_SIGINFO;
  action->sa_sigaction = segfault_handler;
  return action;
}
