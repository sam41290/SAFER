
#pragma once

#define ACCEPT_THRESHOLD 1.79769e+308//powl(2,50)
#define REJECT_THRESHOLD 0 //powl(2,10)
#define CODE_SCORE 6

//#define GROUND_TRUTH

//#define SYM_TABLE_DISASM_ROOT //uses symbol table.

//#define EH_FRAME_DISASM_ROOT //only consider valid code pointer as disasm root.
        //Any relocated pointers within EH frame body considered as valid code pointer.

#define KNOWN_CODE_POINTER_ROOT

//#define DISASMONLY

#define CFGCONSISTENCYCHECK

#define INIT_TYPE 4 //With ABI

#ifdef CFGCONSISTENCYCHECK

#define SP_ANALYSIS

#define NOTSTRING(ptr) notString(ptr) //also checks alignment
#define ALIGNED(ptr) aligned(ptr)
#define IMMOP(ptr) immOperand(ptr)
#define RELOCATEDCONST(ptr) relocatedConst(ptr)
#define RELOCATEDIMMOP(ptr) relocatedImm(ptr)
#define RLTVPTR(ptr) rltvPtr(ptr)

#define SYMBOLIZING_IMM(ptr) IMMOP(ptr)
#define SYMBOLIZING_CONST(ptr) ALIGNED(ptr)
#define SYMBOLIZING_RLTV(ptr) RLTVPTR(ptr)
#define SYMBOLIZING_JMPTBLTGT(ptr) jmpTblTgt(ptr)
#define SYMBOLIZING_COND(ptr) SYMBOLIZING_CONST(ptr) || SYMBOLIZING_RLTV(ptr) || SYMBOLIZING_JMPTBLTGT(ptr)


#define SYMBOLIZEIMMOP(ptr) symbolizeImmOp(ptr)
#define SYMBOLIZEALIGNED(ptr) symbolizeAlignedConst(ptr)
#define SYMBOLIZERELOCATEDCONST(ptr) symbolizeRelocatedConst(ptr)
#define SYMBOLIZERELOCATEDIMM(ptr) symbolizeRelocatedImm(ptr)
#define SYMBOLIZERLTV(ptr) symbolizeRltvPtr(ptr)
#define SYMBOLIZENONSTRING(ptr) symbolizeNonString(ptr)

#define SYMBOLIZE(ptr)

/*
#define SYMBOLIZE(ptr) { \
  SYMBOLIZENONSTRING(ptr); \
  SYMBOLIZEIMMOP(ptr); \
  SYMBOLIZERLTV(ptr); \
}
*/

#define SYMBOLIZABLE(BB) isSymbolizable(BB->start())

#define INSVALIDITY vector <InsValidityRules> {InsValidityRules::VLD_OP,InsValidityRules::VLD_MEM,InsValidityRules::VLD_PRFX,InsValidityRules::VLD_USRMODE_INS}

#define PROPERTIES {Property::VALIDINS, Property::VALID_CF, Property::ABI_REG_PRESERVE_AND_VALID_INIT}
#define DEFDATA(p) \
  ((p == Property::VALIDINS) ? true :\
   (p == Property::VALID_CF) ? true : false)

#define DEFCODE(p) \
  ((p == Property::ABI_REG_PRESERVE_AND_VALID_INIT) ? true :\
   (p == Property::VALIDINIT) ? true : false)

#define TRANSITIVECF Update::LOCAL

#define CFTODEFCODE 0

#define CFTRANSFERDENSITY 0.1

#else
#define SYMBOLIZING_COND(ptr) false

#define SYMBOLIZE(ptr)

#define CFTODEFCODE 0

#define CFTRANSFERDENSITY 0

#define FNCHECK(BB,BBLIST) false

#endif


#define TOOL_PATH "/home/sbr/SBI/"
#define INST_CODE_PATH TOOL_PATH"run/instrumentation_code_here/"
#define INST_BINARY "tutorial"

#define FUNCTION_RANDOMIZATION

//#define NO_BASIC_BLOCK_RANDOMIZATION

#define LLRK_BASIC_BLOCK_RANDOMIZATION
#define LLRK_COMMON_CONSTANT_VALUE 16   //Average partition size

//#define PBR_BASIC_BLOCK_RANDOMIZATION
#define MAX_PBR_PER_BLOCK 10    //Maximum possible trap instructions for PBR
#define PBR_COMMON_CONSTANT_VALUE 20    //Number of blocks

//#define ZJR_BASIC_BLOCK_RANDOMIZATION

#define ENCODE 1
#define ENCCLASS GttAtt

//#define OPTIMIZED_EH_METADATA

