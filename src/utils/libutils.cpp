#include "libutils.h"

using namespace std;

set <string> utils::cf_ins_set {
   "jb",
   "jnae",
   "jc",
   "jbe",
   "jna",
   "jrcxz",
   "jl",
   "jnge",
   "jle",
   "jng",
   "jmp",
   "jmpe",
   "jmpf",
   "jnb",
   "jae",
   "jnc",
   "jnbe",
   "ja",
   "jnl",
   "jge",
   "jnle",
   "jg",
   "jno",
   "jnp",
   "jpo",
   "jns",
   "jnz",
   "jne",
   "jo",
   "jp",
   "jpe",
   "js",
   "jz",
   "je",
   "loop",
   "loopnz",
   "loopne",
   "loopz",
   "loope",
   "call",
   "callf",
   "callq",
   "jmpq",
   "ret",
   "retq" };


set <string> utils::uncond_cf_ins_set {
  "jmp",
  "call",
  "callq",
  "jmpq",
  "retq",
  "ret",
  "jmpq"
};
unordered_set <string> utils::prefixes {
  "rex",
  "rexq",
  "rexz",
  "rep",
  "repz",
  "repq",
  "notrack",
  "lock",
  "repnz",
  "repne",
  "ss",
  "es",
  "fs",
  "gs"
};

unordered_set <string> utils::invalid_prefixes {
  "ss",
  "es",
  "fs",
  "gs"
};

unordered_set <string> utils::ctrl_regs {
  "%cr0",
  "%cr1",
  "%cr2",
  "%cr3",
  "%cr4"
};
unordered_set <string> utils::debug_reg {
    "%dr0",
    "%dr1",
    "%dr2",
    "%dr3",
    "%dr4",
    "%dr5",
    "%dr6",
    "%dr7"
};
unordered_set <string> utils::priviledge_ins {
  "lgdt",
  "lldt",
  "ltr",
  "lmsw",
  "clts",
  "invd",
  "invlpg",
  "wbinvd",
  "rdmsr",
  "wrmsr",
  "rdpmc",
  "rdtsc"
};
