#ifndef COMPACT_COUNTER_H
#define COMPACT_COUNTER_H

#include "CompactFloat.h"

template<class RepType, unsigned MBITS, unsigned EBITS>
class CompactCounter: private CompactFloat<RepType, MBITS, EBITS, 0, 0, 1> {

#define Self CompactCounter<RepType, MBITS, EBITS>
#define Base CompactFloat<RepType, MBITS, EBITS, 0, 0, 1>

   static_assert(MBITS+EBITS <= 8*sizeof(RepType), 
                 "Mantissa and exponent size too large for underlying storage");

   static constexpr RepType maxival=(1ul<<(8*sizeof(RepType)-1));

   constexpr bool isExact() const { return Base::data_ & maxival;};
   constexpr static bool isExact(uint64_t l) { return (l < maxival);};
   constexpr static bool isExact(double d) { 
      return (((uint64_t) d) == d && d < maxival);
   };

   void assignExact(uint64_t l) { Base::data_ = l | maxival;};
   void assignExact(double d)   { assignExact((uint64_t)d);};

 public:
   static double maxf() {return Base::maxf();};

   constexpr CompactCounter() {Base::data_ = maxival;}
   constexpr CompactCounter(int d) {operator=(d);};
   constexpr CompactCounter(uint64_t d) {operator=(d);};
   constexpr CompactCounter(double d) {operator=(d);};
   constexpr CompactCounter(const CompactCounter& o) {operator=(o);};

   constexpr Self& operator=(const Self& o) { 
      Base::data_ = o.Base::data_; 
      return *this;
   };
   constexpr void operator=(int i) {
      uint64_t l = i;
      if (isExact(l))
         assignExact(l);
      else {Base::data_ = 0; Base::operator=(l);}
   }
   constexpr void operator=(uint64_t l) {
      if (isExact(l))
         assignExact(l);
      else {Base::data_ = 0; Base::operator=(l);}
   }
   void operator=(double d) {
      if (isExact(d))
         assignExact(d);
      else {Base::data_ = 0; Base::operator=(d);}
   }

   constexpr bool operator!=(const Self o) const {return !operator==(o);};
   constexpr bool operator!=(uint64_t o) const {return !operator==(o);};
   constexpr bool operator!=(int o) const {return !operator==(o);};
   constexpr bool operator!=(double o) const {return !operator==(o);};

   constexpr bool operator==(const Self o) const {
      return (Base::data_ == o.Base::data_);
   };
   constexpr bool operator==(uint64_t l) const {
      return (((uint64_t)*this) == l);
   };
   constexpr bool operator==(int i) const {
      return (((uint64_t)*this) == ((uint64_t)i));
   };
   constexpr bool operator==(double d) const {
      return (((double)*this)==d);
   };

   Self& operator++() { 
      RepType& l = Base::data_;
      if (l & maxival) {
         if (!(++l))
            Base::operator=((uint64_t)maxival);
      }
      else Base::operator=(Base::operator+(1ul));
      return *this; 
   }

   Self& operator--() { 
      RepType& l = Base::data_;
      if (l & maxival) {
         if (!((--l) & maxival)) // went beloe zero, so
            l = maxival;         // simply reset to zero.
      }
      else Base::operator=(Base::operator-(1ul));
      return *this; 
   }

   Self& operator+=(int i) { inc(i); return *this; }
   Self& operator-=(int i) { dec(i); return *this; }
   Self& operator+=(unsigned i) { inc(i); return *this; }
   Self& operator-=(unsigned i) { dec(i); return *this; }
   Self& operator+=(uint64_t i) { inc(i); return *this; }
   Self& operator-=(uint64_t i) { dec(i); return *this; }

   void inc(uint64_t i) {
      RepType& l = Base::data_;
      if ((l & maxival) && ((l+i)&maxival)) {
            l += i;
            return;
      }
      if (l & maxival)
         operator=((uint64_t)((l&(~maxival)) + i));
      else Base::operator=(Base::operator+((uint64_t)i));
   };

   constexpr void dec(uint64_t i) {
      RepType& l = Base::data_;
      if (l & maxival) {
            l -= i;
            if (!(l&maxival)) // became less than zero, force back to zero
               l = maxival;
      }
      else {
         Base b = Base::operator-((uint64_t)i);
         if (b.exponent() < EBITS+1)
            operator=(b.ulval());
         else Base::operator=(b);
      }
   };

   void inc(int i) { inc((uint64_t)i); }
   constexpr void dec(int i) { dec((uint64_t)i); }
   void inc(unsigned i) { inc((uint64_t)i); }
   constexpr void dec(unsigned i) { dec((uint64_t)i); }

   constexpr operator double() const {
      if (isExact())
         return (Base::data_ & (~maxival));
      else return Base::dval();
   }
   constexpr operator uint64_t() const {
      if (isExact())
         return (Base::data_ & (~maxival));
      else return Base::ulval();
   }

   constexpr operator int() const {
      if (isExact())
         return (int)(Base::data_ & (~maxival));
      else return (int)Base::ulval();
   }

   void print(ostream& os) const {
      if (isExact())
         os << (uint64_t)*this;
      else os << (double)*this;
   }
};

template<class RepType, unsigned MBITS, unsigned EBITS>
ostream& operator<<(ostream& os, const Self& s) {
   s.print(os);
   return os;
};

#undef Self
#undef Base

#endif
