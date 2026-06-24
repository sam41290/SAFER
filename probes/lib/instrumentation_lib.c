/*-----------------------------------------------------------------------

Author: Sousaferakant Priyadarshan
  MS student, Stony Brook University

Description:
  Contains definitions of library functions to be used while building instrumentation code.
  
*------------------------------------------------------------------------*/
#include "instrumentation_lib.h"
#include <sys/syscall.h>  // __NR_*
#include <unistd.h>       // fallback syscall()
#include <fcntl.h>

// Raw: returns kernel return value (0.., or negative -errno)
static inline long sys_call_raw(unsigned long n,
                                unsigned long a1, unsigned long a2, unsigned long a3,
                                unsigned long a4, unsigned long a5, unsigned long a6)
{
#if defined(__x86_64__)
    // x86-64 Linux syscall ABI:
    // rax = nr, rdi = a1, rsi = a2, rdx = a3, r10 = a4, r8 = a5, r9 = a6
    register unsigned long r10 __asm__("r10") = a4;
    register unsigned long r8  __asm__("r8")  = a5;
    register unsigned long r9  __asm__("r9")  = a6;
    register long rax __asm__("rax") = n;
    register unsigned long rdi __asm__("rdi") = a1;
    register unsigned long rsi __asm__("rsi") = a2;
    register unsigned long rdx __asm__("rdx") = a3;

    __asm__ volatile ("syscall"
                      : "+a"(rax)                           // rax = ret
                      : "D"(rdi), "S"(rsi), "d"(rdx),
                        "r"(r10), "r"(r8), "r"(r9)          // pinned via named regs above
                      : "rcx", "r11", "memory");
    return rax;

#elif defined(__aarch64__)
    // AArch64 Linux syscall ABI:
    // x8 = nr, x0..x5 = a1..a6, return in x0
    register unsigned long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register unsigned long x1 __asm__("x1") = a2;
    register unsigned long x2 __asm__("x2") = a3;
    register unsigned long x3 __asm__("x3") = a4;
    register unsigned long x4 __asm__("x4") = a5;
    register unsigned long x5 __asm__("x5") = a6;

    __asm__ volatile ("svc 0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                      : "memory");
    return x0;

#else
    // Fallback: use libc's syscall()
    return syscall(n, a1, a2, a3, a4, a5, a6);
#endif
}

// Friendly wrapper: sets errno and returns -1 on error (like libc syscall())

long sys_call(unsigned long n,
                            unsigned long a1, unsigned long a2, unsigned long a3,
                            unsigned long a4, unsigned long a5, unsigned long a6)
{
    long r = sys_call_raw(n, a1, a2, a3, a4, a5, a6);
    if (r < 0 && r >= -4095) { return -1; }
    return r;
}



void safer_exit() {
  sys_call1(SYS_exit,0);
}

int safer_putchar(int c)
{
  char *buff=(char*)&c;
  long fd=1;
  long count=1;
  unsigned long syscallnumber = 1;
  long write_count;

  write_count = sys_call3(SYS_write, fd, (long)buff,count);
  
  
  if(write_count==1)
  return c;
  else 
  return -1;
}

int safer_puts(const char *s)
{
  for( ; *s; ++s) {
  safer_putchar(*s);
  }
  return 0;
}

int safer_openat(char *file, int flag, unsigned int mode) {
  long fd = sys_call4(SYS_openat, (long)AT_FDCWD, (long)file, (long)flag, (long)mode);
  return fd;
}

void safer_write(char *file, char *msg, int len) {
  int fd = safer_openat(file, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if(fd < 0) {
    int tmp_fd = safer_openat("/tmp/safer_log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if(tmp_fd < 0) {
      safer_puts("Could not open tmp file\n");
    }
    else {
      sys_call3(SYS_write, (long)tmp_fd, (long)msg, (long)len);
    }
  }
  else sys_call3(SYS_write, (long)fd, (long)msg, (long)len);
}


int printfflushint(int text,int ctr,char *args)
{
  char str[1024]; int i = 0;

  if (text == 0)
  {
    str[0] = '0';
    str[1] = '\0';
  }

  while(text)
  {
    str[i++] = (text%10) + '0';
    text/=10;
  }
  str[i] = '\0';
  int j = 0; i--;
  while(j < i)
  {
    char temp = str[i];
    str[i] = str[j];
    str[j] = temp;
    j++;i--;
  }
  for(i=0;str[i]!='\0';i++)
  {
    args[ctr]=str[i];
    ctr++;
  }
  return ctr;
  
}

int printfflushhex(uint64_t num,int ctr,char *args)
{
  char ret[1024];
  
  int r = 0;

  do
  {
  int rem = num%16;
  if (rem >= 10)
  {
    ret[r++] = (char)('a' + rem-10);
  }
  else
  {
    ret[r++] = rem + '0';
  }
  num/=16;
  }while(num);
  ret[r] = '\0';

  //reverse
  r--;
  int i = 0;
  while(i < r)
  {
    char temp = ret[i];
    ret[i] = ret[r];
    ret[r] = temp;
    i++;r--;  
  }
  for(i=0;ret[i]!='\0';i++)
  {
    args[ctr]=ret[i];
    ctr++;
  }
  

  return ctr;
}



int saferprintf(const char *pfmt, ...)
{
  
  char args[1024];
  va_list pap;
  int d;
  char *s, c;
  uint64_t address;

  int i=0;  
  va_start(pap, pfmt);
  while (*pfmt)
  {    
    char ch = (char)*pfmt;
    char nextch = (*(pfmt+1))?(char)*(pfmt+1):'\0';
    if (ch == '%' && nextch == 's')
    {
      s = va_arg(pap, char *);
      for(int j=0;s[j]!='\0';j++)
      {
      args[i]=s[j];
      i++;
      }
      pfmt++;
    }
    else if (ch == '%' && nextch == 'c')
    {
      c = (char) va_arg(pap, int);
      args[i]=c;
      i++;
      pfmt++;
    }
    else if (ch == '%' && nextch == 'd')
    {
      d = va_arg(pap, int);
      i=printfflushint(d,i,args);
      
      pfmt++;
    }
    else if (ch == '%' && nextch == 'x')
    {
      d = va_arg(pap, int);
      i=printfflushhex(d,i,args);
      pfmt++;
    }
    else if (ch == '%' && nextch == 'p')
    {
      address = va_arg(pap, uint64_t);
      i=printfflushhex(address,i,args);
      pfmt++;
    }
    else
    {
      args[i]=ch;
      i++;
      pfmt++;
    }
  }
  va_end(pap);
  args[i]='\0';
  //puts("string parsing complete\n");
  int ret=safer_puts(args);
  return ret;
  
  //kprintf("4");
}

void safermemset(void *p, uint8_t c, int bytes)
{
  for(int i = 0; i < bytes; i++)
  {
    *((uint8_t *)p) = c;
  }
}

/* Biggest signal number + 1 (including real-time signals).  */
#define _NSIG                (__SIGRTMAX + 1)



int safersigaction (int sig, const struct sigaction *act, struct sigaction *oact)
{
  int result;


  int p_sig = sig;

  //act->sa_restorer = (void *)sa_restorer;

  void *p_act = (void *)act;
  void *p_oact = (void *)oact;

  unsigned long sigsetsize = _NSIG / 8;
  unsigned long syscallnumber = 13;

  result = sys_call4(SYS_rt_sigaction, p_sig, (long)act, (long)oact, sigsetsize);

  return result;
}

void *safermmap(uint64_t size){

  unsigned long syscallnumber = 9;
  void *addr = NULL;
  uint64_t length = size;
  int prot = PROT_READ | PROT_WRITE;//PROT_READ;
  int flags = MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE;
    int fd = 0; int offset = 0;
    void* ret = NULL;

  ret = (void *) sys_call6(SYS_mmap, (long)addr, length, prot, flags, fd, offset);

  return ret;
}
