#define FULL_ADDR_TRANS true
#define FULL_ENCODE false 
#define RA_OPT true
#define SAFE_JTABLE true
#define NO_ENCODE_LEAPTRS true

#define ENCODE 1
#define ENCCLASS MultInv
//#define ENCCLASS GttAtt
//#define OPTIMIZED_EH_METADATA

//#define ONE_LEVEL_HASH
#define SHSTK(b) {\
  vector<InstArg> arglst5;\
  b.registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,"GTF_stack",arglst5);\
}

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

//#define SYMBOLIZE(ptr)
#define SYMBOLIZE(ptr) { \
  if(FULL_ADDR_TRANS == false) {\
    SYMBOLIZERELOCATEDCONST(ptr); \
    SYMBOLIZERELOCATEDIMM(ptr); \
    if(NO_ENCODE_LEAPTRS == false)\
      SYMBOLIZERLTV(ptr); \
  }\
}

#define SYMBOLIZABLE(BB) isSymbolizable(BB->start())

