#include "libutils.h"

using namespace std;

set <uint8_t> utils::all_jmp_opcodes {
  0x70,0x71,0x78,0x79,0x74,0x75,0x72,0x73,0x76,0x77,
  0x7c,0x7d,0x7e,0x7f,0x7a,0x7b,0xe3,0xeb,0xe9
};

set <uint8_t> utils::unconditional_jmp_opcodes {
  0xeb,0xe9
};

set <uint8_t> utils::conditional_jmp_opcodes {
  0x70,0x71,0x78,0x79,0x74,0x75,0x72,0x73,0x76,0x77,
  0x7c,0x7d,0x7e,0x7f,0x7a,0x7b,0xe3
};

set <uint8_t> utils::conditional_long_jmp_opcodes {
  0x80,0x81,0x88,0x89,0x84,0x85,0x82,0x83,0x86,0x87,0x8c,0x8d,0x8e,0x8f,0x8a,0x8b
};


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
   "loopq",
   "loopnz",
   "loopne",
   "loopneq",
   "loopz",
   "loope",
   "loopeq",
   "call",
   "callf",
   "callq",
   "jmpq",
   "ret",
   "retq",
   "iret",
   "iretl",
   "iretq"
};


set <string> utils::uncond_cf_ins_set {
  "jmp",
  "call",
  "callq",
  "jmpq",
  "retq",
  "ret",
  "jmpq"
};
unordered_map <uint8_t,string> utils::prefixes {
  {0x40,"rex"     },
  {0x40,"rexq"    },
  {0x40,"rexz"    },
  {0x41,"rex.B"   },
  {0x42,"rex.X"   },
  {0x43,"rex.XB"  },
  {0x44,"rex.R"   },
  {0x45,"rex.RB"  },
  {0x46,"rex.RX"  },
  {0x47,"rex.RXB" },
  {0x48,"rex.W"   },
  {0x49,"rex.WB"  },
  {0x4a,"rex.WX"  },
  {0x4b,"rex.WXB" },
  {0x4c,"rex.WR"  },
  {0x4d,"rex.WRB" },
  {0x4e,"rex.WRX" },
  {0x4f,"rex.WRXB"},
  {0xf3,"rep"     },
  {0xf3,"repz"    },
  {0xf3,"repq"    },
  {0x3e,"notrack" },
  {0xf0,"lock"    },
  {0xf2,"repnz"   },
  {0xf2,"repne"   },
  {0x2e,"ss"      },
  {0x26,"es"      },
  {0x64,"fs"      },
  {0x65,"gs"      },
  {0x2e,"cs"      },
  {0x3e,"ds"      }
};

unordered_set <string> utils::prefix_ops {
  {"rex"     },
  {"rexq"    },
  {"rexz"    },
  {"rex.B"   },
  {"rex.X"   },
  {"rex.XB"  },
  {"rex.R"   },
  {"rex.RB"  },
  {"rex.RX"  },
  {"rex.RXB" },
  {"rex.W"   },
  {"rex.WB"  },
  {"rex.WX"  },
  {"rex.WXB" },
  {"rex.WR"  },
  {"rex.WRB" },
  {"rex.WRX" },
  {"rex.WRXB"},
  {"rep"     },
  {"repz"    },
  {"repq"    },
  {"notrack" },
  {"lock"    },
  {"repnz"   },
  {"repne"   },
  {"ss"      },
  {"es"      },
  {"fs"      },
  {"gs"      },
  {"cs"      },
  {"ds"      },
  {"addr32"  },
  {"bnd"  },
  {"data16"  }
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
  "lidt",
  "ltr",
  "lmsw",
  "clts",
  "invd",
  "invlpg",
  "wbinvd",
  "wbnoinvd",
  "rdmsr",
  "wrmsr",
  "rdpmc",
  "in",
  "out",
  "inl",
  "inb",
  "insb",
  "insl",
  "outb",
  "outl",
  "outsl",
  "outsb",
  "outs",
  "swapgs",
  "ljmp",
  "ljmpl",
  "iret",
  "iretq",
  "iretl"
};
