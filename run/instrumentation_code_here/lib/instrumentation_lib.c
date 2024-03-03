/*-----------------------------------------------------------------------

Author: Soumyakant Priyadarshan
  MS student, Stony Brook University

Description:
  Contains definitions of library functions to be used while building instrumentation code.
  
*------------------------------------------------------------------------*/
#include "instrumentation_lib.h"

void my_exit() {
  __asm__(
  "movq $60, %rax;\n"
  "movq $0, %rdi;\n"
  "syscall;\n"
  );
}

int my_putchar(int c)
{
  char *buff=(char*)&c;
  long fd=1;
  long count=1;
  unsigned long syscallnumber = 1;
  long write_count;

  __asm__(
  "movq %1, %%rax;\n"
  "movq %2, %%rdi;\n"
  "movq %3, %%rsi;\n"
  "movq %4, %%rdx;\n"
  "syscall;\n"
  "movq %%rax, %0;\n"
  : "=m" (write_count)
  : "m" (syscallnumber), "m" (fd), "m" ((unsigned long)buff), "m" (count)
  : "rax","rdi", "rsi", "rdx"
  );

  if(write_count==1)
  return c;
  else 
  return -1;
}

int my_puts(const char *s)
{
  for( ; *s; ++s) {
  my_putchar(*s);
  }
  return 0;
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



int myprintf(const char *pfmt, ...)
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
  int ret=my_puts(args);
  return ret;
  
  //kprintf("4");
}

void mymemset(void *p, uint8_t c, int bytes)
{
  for(int i = 0; i < bytes; i++)
  {
    *((uint8_t *)p) = c;
  }
}

/* Biggest signal number + 1 (including real-time signals).  */
#define _NSIG                (__SIGRTMAX + 1)



int mysigaction (int sig, const struct sigaction *act, struct sigaction *oact)
{
  int result;


  int p_sig = sig;

  //act->sa_restorer = (void *)sa_restorer;

  void *p_act = (void *)act;
  void *p_oact = (void *)oact;

  unsigned long sigsetsize = _NSIG / 8;
  unsigned long syscallnumber = 13;

  __asm__(
  "movq %1, %%rax;\n"
  "movq %2, %%rdi;\n"
  "movq %3, %%rsi;\n"
  "movq %4, %%rdx;\n"
  "movq %5, %%r10;\n"
  "syscall;\n"
  "movq %%rax, %0;\n"
  : "=m" (result)
  : "m" (syscallnumber),"m" (p_sig), "m" (act), "m" (oact), "m" (sigsetsize)
  : "rax","rdi", "rsi", "rdx", "r10"
  );


  return result;
}

void *mymmap(uint64_t size){

  unsigned long syscallnumber = 9;
  void *addr = NULL;
  uint64_t length = size;
  int prot = PROT_READ | PROT_WRITE;//PROT_READ;
  int flags = MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE;
    int fd = 0; int offset = 0;
    void* ret = NULL;

  __asm__(
  "movq %1,%%rax;\n"
  "movq %2,%%rdi;\n"
  "movq %3,%%rsi;\n"
  "movq %4,%%rdx;\n"
  "movq %5,%%r10;\n"
  "movq %6,%%r9;\n"
  "movq %7,%%r8;\n"
  "syscall;\n"
  "movq %%rax, %0"
  :"=m"(ret)
  :"m"(syscallnumber),"m"((uint64_t)addr),"m"(length),"m"(prot),"m"(flags),"m"(fd),"m"(offset)
  );

  return ret;
}
