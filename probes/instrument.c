#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include "instrumentation_lib.h"

void LOG(uint64_t rip)
{
  saferprintf("Basic Block reached: %p\n", rip);
}

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>     // offsetof
#include <stdlib.h>     // calloc, free
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#if defined(__x86_64__)
#  define ARCH_AUDIT  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define ARCH_AUDIT  AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#  define ARCH_AUDIT  AUDIT_ARCH_I386
#else
#  error "Add your arch to ARCH_AUDIT"
#endif

#define ArchField offsetof(struct seccomp_data, arch)

void install_syscall_filter(const int *allow_list, int *len_ptr)
{
  
  int len = *len_ptr;

  //saferprintf("Adding syscall filter...\n");
  //saferprintf("Syscall count %d\n", len);

  /* prog layout: 3 (arch check) + 1 (load nr) + 2*len (allow rules) + 1 (default) */
  const int n_insn = 3 + 1 + 2*len + 1;
  //saferprintf("filter size %d\n", n_insn);
  struct sock_filter filter[n_insn];
  
  int i = 0;
  
  /* Load arch field */
  filter[i++] = (struct sock_filter){ 
      .code = BPF_LD | BPF_W | BPF_ABS, 
      .jt   = 0, 
      .jf   = 0, 
      .k    = ArchField 
  };
  
  /* Compare arch with ARCH_AUDIT, jump if equal */
  filter[i++] = (struct sock_filter){ 
      .code = BPF_JMP | BPF_JEQ | BPF_K, 
      .jt   = 1, 
      .jf   = 0, 
      .k    = ARCH_AUDIT 
  };
  
  /* Kill if arch mismatch */
  filter[i++] = (struct sock_filter){ 
      .code = BPF_RET | BPF_K, 
      .jt   = 0, 
      .jf   = 0, 
      .k    = SECCOMP_RET_KILL // Change to KILL 
  };
  
  /* Load syscall number */
  filter[i++] = (struct sock_filter){ 
      .code = BPF_LD | BPF_W | BPF_ABS, 
      .jt   = 0, 
      .jf   = 0, 
      .k    = offsetof(struct seccomp_data, nr) 
  };
  
  /* Allow list generated from input array */
  for (int j = 0; j < len; ++j) {
      int sys = allow_list[j];
      

      //saferprintf("Allow syscall %d\n", sys);
  
      /* If syscall == nr, jump forward 1 */
      filter[i++] = (struct sock_filter){ 
          .code = BPF_JMP | BPF_JEQ | BPF_K, 
          .jt   = 0, 
          .jf   = 1, 
          .k    = sys 
      };
  
      /* Allow */
      filter[i++] = (struct sock_filter){ 
          .code = BPF_RET | BPF_K, 
          .jt   = 0, 
          .jf   = 0, 
          .k    = SECCOMP_RET_ALLOW 
      };
  }
  
  /* Default: kill everything else */
  filter[i++] = (struct sock_filter){ 
      .code = BPF_RET | BPF_K, 
      .jt   = 0, 
      .jf   = 0, 
      .k    = SECCOMP_RET_KILL // Change to KILL
  };


  struct sock_fprog prog = {
    .len    = (unsigned short)i,
    .filter = filter
  };

  /* Required on most kernels before enabling a filter */
  if (sys_call5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        saferprintf("Could not set PR_SET_NEW_PRIVS\n");
        safer_exit();
  }

  if (sys_call5(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&prog, 0, 0) != 0) {
        saferprintf("Could not start seccomp\n");
        safer_exit();
  }
  //saferprintf("syscall filter added\n");

}

int cstr_len(char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n] != '\0') n++;
    return n;
}

void write_string(char *file, char *msg) {
  int len = cstr_len(msg);
  safer_write(file, msg, len);
  safer_write(file, "\n", 1);
}


//
//#define Allow(syscall) \
//    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
//    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
//
//#define AllowNR(NR) \
//    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, NR, 0, 1), \
//    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
//
//#define Kill(syscall) \
//    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
//    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_Kill)
//
//void install_syscall_filter(int allow_list[], int len) {
//    saferprintf("Adding syscall filter...\n");
//    struct sock_filter filter[] = {
//        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
//        BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
//        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
//    
//        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
//    
//        Allow(exit_group),
//        Allow(brk),
//        Allow(mmap),
//        Allow(munmap),
//        Allow(write),
//        Allow(fstat),
//        Allow(execve),
//        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
//    };
//    struct sock_fprog filterprog2 = {
//        .len = sizeof(filter)/sizeof(filter[0]),
//        .filter = filter
//    };
//    if (sys_call5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
//        saferprintf("Could not set PR_SET_NEW_PRIVS\n");
//        safer_exit();
//    }
//    if (sys_call5(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&filterprog2,0,0) == -1) {
//    //if (sys_call5(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_STRICT,0,0,0) == -1) {
//        saferprintf("Could not start seccomp\n");
//        safer_exit();
//    }
//    saferprintf("syscall filter added\n");
//
//}

//
//void install_syscall_filter() {
//    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
//        perror("Could not start seccomp:");
//        exit(1);
//    }
//    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
//        perror("Could not start seccomp:");
//        exit(1);
//    }
//
//}
//
//int main() {
//    install_syscall_filter();
//}
