#define ACCEPT_THRESHOLD 1.79769e+308//powl(2,50)
#define REJECT_THRESHOLD 0 //powl(2,10)
#define CODE_SCORE 0

//#define GROUND_TRUTH

//#define SYM_TABLE_DISASM_ROOT //uses symbol table.

//#define EH_FRAME_DISASM_ROOT //only consider valid code pointer as disasm root.
        //Any relocated pointers within EH frame body considered as valid code pointer.

#define KNOWN_CODE_POINTER_ROOT

#define CFGCONSISTENCYCHECK

#define INIT_TYPE 4 //With ABI

#ifdef CFGCONSISTENCYCHECK

#define SP_ANALYSIS

#define INSVALIDITY vector <InsValidityRules> {InsValidityRules::VLD_OP,InsValidityRules::VLD_MEM,InsValidityRules::VLD_PRFX,InsValidityRules::VLD_USRMODE_INS}

/*
#define PROPERTIES {Property::VALIDINS, Property::VALID_CF, Property::ABI_REG_PRESERVE_AND_VALID_INIT}
#define DEFDATA(p) \
  ((p == Property::VALIDINS) ? true :\
   (p == Property::VALID_CF) ? true : false)

#define DEFCODE(p) \
  ((p == Property::ABI_REG_PRESERVE_AND_VALID_INIT) ? true :\
   (p == Property::VALIDINIT) ? true : false)

*/

#define PROPERTIES {Property::VALIDINS, Property::VALID_CF}
#define DEFDATA(p) \
  ((p == Property::VALIDINS) ? true :\
   (p == Property::VALID_CF) ? true : false)

#define DEFCODE(p) \
  ((p == Property::ABI_REG_PRESERVE_AND_VALID_INIT) ? true :\
   (p == Property::VALID_CF) ? true :\
   (p == Property::VALIDINIT) ? true : false)

#define TRANSITIVECF Update::LOCAL

#define CFTODEFCODE 0

#define CFTRANSFERDENSITY 0.1

#else

#define CFTODEFCODE 0

#define CFTRANSFERDENSITY 0

#define FNCHECK(BB,BBLIST) false

#endif
