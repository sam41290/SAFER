#ifndef COMPACT_TAG_H
#define COMPACT_TAG_H

#include "CompactFloat.h"

//This class is mainly introduced to gain access to the data_ field in protected
//mode from CompactFloat. The data_ field is required for probabilitic tag to
//convert the RepType to be converted into a CompactFloat type. This is
//introduced here using the constructor. Also by default the last three element
//of the template class is set to NEG=0, ENEG=1 and EPOS=0.

template<class RepType, unsigned MBITS, unsigned EBITS>
class CompactTag : public CompactFloat<RepType, MBITS, EBITS, 0, 1, 0> { 

#define Base CompactFloat<RepType, MBITS, EBITS, 0, 1, 0>
   
 public:
   constexpr CompactTag(RepType v): Base() { Base::data_ = v; }
   constexpr CompactTag(double d): Base(d) {}

};

#undef Base
#endif
