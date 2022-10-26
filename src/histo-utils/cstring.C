#include "cstring.h"
#ifdef MT
mutex CRefCtBuf::lk[8];
#endif
