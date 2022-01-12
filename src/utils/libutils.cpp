#include "libutils.h"

using namespace std;
unordered_map <uint64_t, string> utils::sym_bindings;
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
unordered_map <string,uint8_t> utils::prefixes {
  {"rex",0x40},
  {"rexq",0x40},
  {"rexz",0x40},
  {"rex.B",0x41},
  {"rex.X",0x42},
  {"rex.XB",0x43},
  {"rex.R",0x44},
  {"rex.RB",0x45},
  {"rex.RX",0x46},
  {"rex.RXB",0x47},
  {"rex.W",0x48},
  {"rex.WB",0x49},
  {"rex.WX",0x4a},
  {"rex.WXB",0x4b},
  {"rex.WR",0x4c},
  {"rex.WRB",0x4d},
  {"rex.WRX",0x4e},
  {"rex.WRXB",0x4f},
  {"rep",0xf3},
  {"repz",0xf3},
  {"repq",0xf3},
  {"notrack",0x3e},
  {"lock",0xf0},
  {"repnz",0xf2},
  {"repne",0xf2},
  {"ss",0x2e},
  {"es",0x26},
  {"fs",0x64},
  {"gs",0x65},
  {"cs",0x2e},
  {"ds",0x3e}
};

unordered_set <string> utils::invalid_prefixes {
  "ss",
  "es",
  "fs",
  "gs",
  "cs",
  "ds"
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
