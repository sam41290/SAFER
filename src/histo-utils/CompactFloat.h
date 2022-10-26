#ifndef COMPACT_FLOAT_H
#define COMPACT_FLOAT_H

#include "Base.h"
#include <ieee754.h>
#include <cmath>

#define RANDOMIZED_CORRECTION

//#define PASTER(x,y) x ## y
//#define EVALUATOR(x,y)  PASTER(x,y)
//#define nextr EVALUATOR(cf_nextr, CORRNG)

#define nextr cf_nextr16

#ifdef TRACK
extern double diff;
extern double sumr;
extern long nadj;
#endif
/*
 * Compact float can represent floating point (or long) values using fewer bits
 * at the cost of reduced precision. The class is parameterized by:
 *   -- MBITS denotes the number of mantissa bits.
 *   -- EBITS denotes the number of exponent bits
 *   -- NEG indicates if negative numbers need to be represented
 *   -- ENEG indicates if negative exponents need to be represented
 *   -- EPOS indicates if positive exponents need to be represented
 */

template<class RepType, unsigned MBITS, unsigned EBITS, bool NEG=true, 
         bool ENEG=true, bool EPOS=true>
class CompactFloat {
#define Self CompactFloat<RepType, MBITS, EBITS, NEG, ENEG, EPOS>
 protected:
   RepType data_;

 private:
   //static_assert(__GCC_IEC_559 > 0, "Only IEEE 754 float supported");
   static_assert(std::is_unsigned<RepType>::value, "RepType must be unsigned");
   static_assert(sizeof(RepType)<=8, "Expect storage type with <= 64 bits");
   static_assert(EBITS+(ENEG^EPOS) <= 10, "Maximum exponent size exceeded");
   static_assert(MBITS <= 53, "Maximum 53-bit mantissa field supported");
   static_assert(MBITS >=  3, "Minimum 3-bit mantissa field required");
   static_assert(MBITS+EBITS+NEG-1 <= 8*sizeof(RepType), 
                 "Mantissa and exponent size too large for underlying storage");
   static_assert(ENEG | EPOS, "Either ENEG or EPOS should be set");

   class IEEE754D { // Wrapper to avoid warning of missing default constructor 
   public:
      ieee754_double id;
      constexpr IEEE754D() { id.d = 0; };
   };

   inline static constexpr int EXP_INF = (1<<EBITS)-EPOS;
   inline static constexpr int EXP_MAX = EXP_INF-1;
   inline static constexpr int EXP_BIAS = 
       (ENEG && EPOS)? (EXP_MAX>>1) : (EPOS? 2-MBITS : EXP_MAX);
   inline static constexpr int MAXEXP = EXP_MAX - EXP_BIAS;
   inline static constexpr int MAXSHIFT = min(63, max((int)(MBITS<<1),30));

   /* Looks like the distribution is fairly reliable into 1 per 1 to 5M range:
      With 100M trials, number of leading zero bits follows expected number ---
      within 20% or so --- starting from 21, may be even up to 23. */ 
 
   static uint64_t cf_nextr(int shift=0) { 
      static const unsigned long a = 6364136223846793005ul; // Knuth's MMIX lin.
      static const unsigned long c = 1442695040888963407ul; // cong. random gen
      static uint64_t r;
      static const int width = 64;
      r = a*r + c;
      if (width < shift)
         return r << (shift-width);
      else return r;
   };

   static uint64_t cf_nextr31(int shift=0) { 
      static const unsigned a=1103515245;
      static const unsigned c=12345;
      static unsigned r=1;
      static const int width = 31;
      r = a*r + c;
      unsigned long rv= r & 0x7fffffff;
      if (width < shift)
         return rv << (shift-width);
      else return rv;
   };

   static uint64_t cf_nextr16(int shift=0) { 
      static const unsigned short a=65533;
      static const unsigned short c=30031;
      static unsigned short r=1;
      static const int width = 16;
      r = a*r + c;
      unsigned long rv=r;
      if (width < shift)
         return rv << (shift-width);
      else return rv;
   };

   constexpr void neg(bool b) { 
      assert_fix(NEG, return);
      setbf(data_, 0, b);
   }

public:
   constexpr unsigned exponent() const {return getbfs(data_, NEG, mask(EBITS));};
   constexpr void exponent(unsigned e) {setbfs(data_, NEG, e, mask(EBITS));};

   constexpr uint64_t mantissa() const {
      return getbfs(data_, NEG+EBITS, mask(MBITS-1));
   }
   constexpr void mantissa(uint64_t m) {
     setbfs(data_, (NEG+EBITS), m, mask(MBITS-1));
   };

   constexpr static Self maxv() {
      Self d;
      d.mantissa((1ul << (MBITS-1))-1);
      d.exponent(EXP_MAX);
      return d;
   }

public:
   inline static double maxf() {return maxv().dval();};

   inline static double minf() {
      if (NEG) return -maxf(); else return 0.0;
   };

   inline static double minpos() {
      Self d;
      d.mantissa(1ul);
      d.exponent(0);
      return d.dval();
   }

   inline constexpr CompactFloat(): data_(0) {};
   //inline constexpr CompactFloat(RepType data): data_(data) {};

   inline constexpr bool neg() const { return (NEG && getbf(data_, 0)); };
   RepType data() const { return data_; };

   inline CompactFloat(double d): data_(0) {
      operator=(d);
   }

   inline constexpr CompactFloat(int64_t l): data_(0) {
      operator=(l);
   }

   inline constexpr CompactFloat(uint64_t l): data_(0) {
      operator=(l);
   }

   inline constexpr bool isInf() const {
      return exponent() == EXP_INF && mantissa() == 0ul; 
   }

   inline constexpr bool isNan() const { 
      return exponent() == EXP_INF && mantissa() != 0ul; 
   }

   inline constexpr bool isZero() const { 
      return exponent() == 0 && mantissa() == 0ul; 
   }

   constexpr Self& operator=(const Self& o) { data_ = o.data_; return *this;};

   inline constexpr bool operator!=(const Self o) const {return !operator==(o);};
   inline constexpr bool operator==(const Self o) const { 
      return (data_ == o.data_);
   };

   inline constexpr Self operator+(double d) const { return operator+(Self(d));};
   inline constexpr Self operator-(double d) const { return operator-(Self(d));};
   inline constexpr Self operator+(long d) const { return operator+(Self(d));};
   inline constexpr Self operator-(long d) const { return operator-(Self(d));};
   inline constexpr Self operator+(uint64_t d)const {return operator+(Self(d));};
   inline constexpr Self operator-(uint64_t d)const {return operator-(Self(d));};
   inline constexpr Self operator*(double d) const { return operator*(Self(d));};
   inline constexpr Self operator/(double d) const { return operator/(Self(d));};
   inline constexpr Self operator*(long d) const { return operator*(Self(d));};
   inline constexpr Self operator/(long d) const { return operator/(Self(d));};
   inline constexpr Self operator*(uint64_t d)const {return operator*(Self(d));};
   inline constexpr Self operator/(uint64_t d)const {return operator/(Self(d));};

   void operator=(double d) {
      IEEE754D df;
      df.id.d = d;
      if (NEG)
         neg(df.id.ieee.negative);

      int e = df.id.ieee.exponent - IEEE754_DOUBLE_BIAS + EXP_BIAS;
      uint64_t m = df.id.ieee.mantissa0;
      m = (m << 32) | df.id.ieee.mantissa1;
      if (MBITS < 53)              // Means we are dropping some bits.
         m += (1ul << (52-MBITS)); // So, use rounding instead of just dropping. 
      m = m >> (53-MBITS);
      if (m & (1ul<<(MBITS-1))) { // Rounding has caused overflow, so shift right
         m = (m & ~(1ul<<(MBITS-1))) >> 1; // and increase exponent by 1. Fix the
         e++; // lead bit --- it would be 0 if implicit lead bit was included.
      }
      
      if (e >= EXP_INF) {
         exponent(EXP_INF);
         mantissa(isnan(d)? (1ul<<(MBITS-2))|1 : 0);
         return;
      }

      if (e <= 0) { // Too small
         exponent(0);
         m |= (1ul<<(MBITS-1)); // Add back the implicit leading 1-bit.
         mantissa((1-e < 64)? m >> (1-e) : 0);
         return;
      }

      mantissa(m);
      exponent(e);
   }

   double dval() const {
      IEEE754D df;
      uint64_t m = mantissa();
      int e = exponent();
      df.id.ieee.negative = neg();
      df.id.ieee.exponent = IEEE754_DOUBLE_BIAS + e - EXP_BIAS;
      if (e == 0) {
         if (m == 0)
            df.id.ieee.exponent = 0;
         else {
            int shift = MBITS - 64 + __builtin_clzl(m);
            df.id.ieee.exponent -= (shift-1);
            m = m << shift; // Ensures leading bit will be 1 (normal form)
         }
      }
      else if (e == EXP_INF) {
         df.id.ieee.exponent = (1<<11)-1;
         df.id.ieee.mantissa0 = ((m >> (MBITS-2)) << 19); // Preserve lead+trail
         df.id.ieee.mantissa1 = ((m << (MBITS-2)) >> 31); // bit: handles inf,nan
         return df.id.d;
      }

      m = m << (53-MBITS); // Lead bit at pos 53 now, so goes out of mantissa0
      df.id.ieee.mantissa0 = m >> 32;
      df.id.ieee.mantissa1 = m;
      return df.id.d;
   }

   constexpr void operator=(uint64_t l) {
      if (ENEG)
         return operator=((double)l);
      if (l == 0) {
         mantissa(0);
         exponent(0);
      }
      else {
         unsigned nbits = 64 - __builtin_clzl(l); // # of significant digits in l
         if (nbits <= MBITS) { // All bits stored, no need to round
            mantissa(l); // Note if nbits==MBITS, leading bit is being implicitly
                // stripped off here in the assignment (normal form of mantissa).
            exponent(nbits == MBITS? 1 : 0); // EXP_BIAS=2-MBITS, so exponent(1)
                // means exp of 1-(2-MBITS) = MBITS-1. If MBITS=4, mantissa(001)
                // and exponent(1) will denote 1.001e3, i.e., the case l=9.
         }
         else {
            uint64_t l1 = l;
            l += 1ul << (nbits - MBITS - 1);
            if (l1 > l) // Rounding caused overflow, don't round
               l = l1;
            l = l >> (nbits-MBITS); // shift out excess LS bits beyond MBITS
            int e = nbits - 1 + EXP_BIAS; // For nbits digit number in normal 
               // form, the exponent is nbits-1. Add bias and store the result.
            if (l & (1ul<<MBITS)) { // This means that rounding caused the #
               e++;                 // of digits to increase to nbits+1. So, we
               l = l>>1;            // incr exponent, shift out one more LSbit
            }
            if (e >= EXP_INF) {
               exponent(EXP_INF);
               mantissa(0);
            }
            else {
               exponent(e);
               mantissa(l);
            }
         }
      }
   }

   constexpr unsigned long ulval() const {
      if (ENEG)
         return dval();
      long rv = mantissa();
      int e = exponent();
      if (e == 0)
         return rv;
      else {
         rv |= (1ul<<(MBITS-1)); // Add back leading mantissa bit
         e -= EXP_BIAS;
         return rv << (e-(MBITS-1)); // rv represents a value that has already
      }  // been shifted left by MBITS-1 bits, so we take that off e.
      // @@@@ NOTE: Overflow (and inifinity, nan) NOT handled.
   }

   constexpr void operator=(int64_t l) {
      if (ENEG)
         return operator=((double)l);
      if (l < 0) {
         if (NEG) {
            neg(true);
            operator=((uint64_t)(-l));
         }
         else {
            mantissa(0);
            exponent(0);
         }
      }
      else {
         if (NEG) neg(false);
         operator=((uint64_t)l);
      }
   }

   inline constexpr long lval() const { 
      if (ENEG) return dval();
      long l = ulval();           // Due to rounding, a +ve number may become
      if (l < 0) l = (1ul<<63)-1; // -ve. Correct by replacing w/ max +ve #.
      if (neg()) return -l; else return l; 
   }

private:
   constexpr Self umax(Self o) const { 
      if (exponent() == o.exponent())
         return (mantissa() > o.mantissa())? *this : o;
      else return (exponent() > o.exponent())? *this : o;
   }

   constexpr Self umin(Self o) const { return (umax(o) == o)? *this : o; };

   constexpr Self smax(Self o) const {
      if (NEG) {
         if (neg())
            if (!o.neg())
               return o;
            else return umin(o);
         else if (o.neg())
            return *this;
         else return umax(o);
      }
      else return umax(o);
   }

   constexpr Self smin(Self o) const { return (smax(o) == o)? *this : o; };

   constexpr void addSameSign(Self a, Self b) {
      unsigned aexp = a.exponent(), bexp = b.exponent();
      uint64_t ma = a.mantissa(); uint64_t mb = b.mantissa(); 
      if (aexp < bexp) {
         aexp = b.exponent(); bexp = a.exponent();
         ma = b.mantissa(); mb = a.mantissa(); 
      }

      // Note: aexp >= bexp >= 0
      if (aexp == 0) {
         //cout << "here\n";
         ma += mb;
         exponent(ma >> (MBITS-1)); // Overflowed bit is implied when exp 
         mantissa(ma); // becomes 1, so no need to shift mantissa right
         return;
      }

      unsigned shift = aexp-bexp;
      if (aexp == EXP_INF || shift >= MAXSHIFT) {
         exponent(aexp);
         mantissa((bexp==EXP_INF && mb != 0)? mb : ma);
         return;
      }

      // equalize exponents and proceed
      unsigned extra = 63-MBITS;
      if (bexp == 0)
         mb = ((mb << extra) >> (shift - 1));
      else mb = ((1ul << 62) | (mb << extra)) >> shift;
      ma = (1ul << 62) | (ma << extra);
      ma += mb;
#ifdef RANDOMIZED_CORRECTION
      uint64_t r1 = nextr(extra);
      uint64_t r = r1 & ((1ul<<extra)-1);
#ifdef TRACK
      double d2 = ((double)ma)/(1ul<<extra);
      diff += (d2-((ma+r) >> extra));
      sumr += r1;
      nadj++;
#endif
      ma += r;
      //(cf_nextr() >> (MBITS+1)));
#endif
      if (ma >> 63) {
         exponent(aexp+1);
         mantissa(ma >> (extra+1));
         if (aexp+1 == EXP_INF)
            mantissa(0); // indicate infinity
      }
      else {
         exponent(aexp);
         mantissa(ma >> extra);
      }
   }

   constexpr void subSameSign(Self a, Self b) { // Note: a > b
      int aexp = a.exponent(), bexp = b.exponent();
      if (aexp == bexp) { // Handle this separately, so that we always get x-x=0.
         // Randomized calc., used with unequal exponents, won't ensure this.
         if (aexp == EXP_INF) {// Infinity and Nan
            exponent(EXP_INF);
            mantissa((1ul<<(MBITS-2)) | 1); // Nan
         }
         else {
            uint64_t m = a.mantissa();
            m -= b.mantissa();
            if (m == 0) {
               mantissa(0);
               exponent(0);
            }
            else if (aexp == 0) {
               exponent(0);
               mantissa(m);
            }
            else { // Note aexp > 0
               int shift = MBITS - 64 + __builtin_clzl(m);
               if (aexp <= shift) {
                  exponent(0);
                  mantissa(m << (aexp-1));
               }
               else {
                  mantissa(m << shift);
                  exponent(aexp-shift);
               }
            }
         }
      }
      else {  // equalize exponents and proceed: Note aexp > bexp since a > b
         if (aexp == EXP_INF) {
            exponent(aexp);
            mantissa((1ul<<(MBITS-2)) | 1); // Nan
         }
         else if (aexp - bexp > MAXSHIFT) {
            exponent(aexp);
            mantissa(a.mantissa());
         }
         else { 
            unsigned extra = 63 - MBITS;
            uint64_t m1  = a.mantissa();
            m1 = m1 << extra;
            uint64_t m = (1ul << 62) | m1;
            uint64_t mb=0;
            uint64_t mb1 = b.mantissa();
            mb1 = mb1 << extra;
            if (bexp == 0)
               mb = (mb1 >> (aexp - bexp - 1));
            else {
               mb = (1ul << 62) | mb1;
               mb = (mb >> (aexp - bexp));
            }
            m -= mb;
#ifdef RANDOMIZED_CORRECTION
            m += nextr(extra) & ((1ul<<extra)-1);
            //m += 1ul<<(extra-1);
#endif
            m >>= extra;
            if (m == 0) {
               mantissa(0);
               exponent(0);
            }
            else {
               int shift = MBITS - 64 + __builtin_clzl(m);
               if (aexp <= shift) {
                  exponent(0);
                  mantissa(m << (aexp-1)); // Note aexp > 0
               }
               else {
                  mantissa(m << shift);
                  exponent(aexp-shift);
               }
            }
         }
      }
   }

public:
   constexpr Self operator+(Self o) const {
      Self rv;
      if (NEG) {
         if (neg() == o.neg()) {
            rv.neg(neg());
            rv.addSameSign(*this, o);
         }
         else if (umax(o) == o) {
            rv.neg(o.neg());
            rv.subSameSign(o, *this);
         }
         else {
            rv.neg(neg());
            rv.subSameSign(*this, o);
         }
      }
      else rv.addSameSign(*this, o);
      return rv;
   }

   constexpr Self operator-(Self o) const {
      Self rv;
      if (NEG) {
         o.neg(!o.neg());
         return operator+(o);
      }
      else {
         if (smax(o) == o)    // Can't subtract larger from smaller number. Set
            return Self(0ul); // to zero. (Aborting seems too disruptive.)
         //assert_fix(smax(o) != o, return rv);
         rv.subSameSign(*this, o);
         return rv;
      }
   }

   // This code has been carefully analyzed, there is no way to improve 
   // performance. Various simplifications such as leaving out inf/nan handling
   // don't make any difference. A 15% boost is obtained by leaving out
   // any rounding, but that seems not worth it.
   constexpr Self operator*(Self b) const {
      Self rv;
      const Self& a=*this;

      if (MBITS >= 32 || ENEG)
         return Self(dval()*b.dval());

      if (NEG)
         rv.neg(a.neg() ^ b.neg());

      int aexp = a.exponent(), bexp = b.exponent();
      uint64_t ma = a.mantissa(), mb = b.mantissa();
      if (aexp != 0)
         ma = ((1<<(MBITS-1)) | ma);
      else aexp++;
      if (bexp != 0)
         mb = ((1<<(MBITS-1)) | mb);
      else bexp++;
      int exp = aexp+bexp-1;
      ma *= mb;

      if (exp >= EXP_INF) {
         rv.exponent(EXP_INF);
         if (a.isNan() || b.isNan() || a.isZero() || b.isZero())
            rv.mantissa((1ul<<(MBITS-2))|1); // indicate nan
         else rv.mantissa(0); // indicate infinity
      }
      else {
         if (ma < (1<<MBITS)) {
            rv.mantissa(ma);
            rv.exponent(exp);
            if (ma < (1<<(MBITS-1)) && exp == 1)
               rv.exponent(0);
            else if (ma == 0) rv.exponent(0);
         }
         else {
            int extra = __builtin_clzl(ma) - 1;
            ma = ma << extra;     // ma's 2 leading bits are 01.
#ifdef RANDOMIZED_CORRECTION
            ma += nextr(64)>>(MBITS+1); // Randomized rounding.
#endif
            int inc = ma >> 63;
            int shift = 63-MBITS+inc; // How far to shift ma to get to NF.
            exp += shift-extra;   // It can be shown that shift-extra >= 1

            rv.mantissa(ma >> shift);
            rv.exponent(exp);
            if (exp >= EXP_INF) {
               rv.exponent(EXP_INF);
               rv.mantissa(0); // indicate infinity
            }

         }
      }
      return rv;
   }

   constexpr Self operator/(Self o) const {
      return Self(dval()/o.dval());
   }
};

using CompactUShort = CompactFloat<uint8_t,  5,4,0,0,1>;
using CompactShort  = CompactFloat<uint8_t,  4,4,1,0,1>;
using CompactULong  = CompactFloat<uint16_t,11,6,0,0,1>;
using CompactLong   = CompactFloat<uint16_t,10,6,1,0,1>;
template <unsigned TOTBITS, unsigned EBITS=max((TOTBITS+2)/3,4u)>
using CompactProb   = CompactFloat<uint16_t,TOTBITS+1-EBITS,EBITS,0,1,0>;

#undef Self

// NOTE: There is no benefit in using a base > 2 for exponent. Suppose that we
// use a mantissa of m bits, an exponent base of 2^n, and k-bits for storing
// exponent. The max value that can be stored is (2^n)^(2^k) = 2^(n*2^k). Since
// we can no longer ensure that the leading bit is 1, we lose up to n bits of
// precision in the mantissa, for an effective (worst-case) size of m-n. But if
// used an exponent base of 2, we would need
//      log log 2^(n*2^k) bits = log (n*2^k) = log n + k bits,
// which would allow a mantissa size of m-log(n) > m-n bits.

#endif
