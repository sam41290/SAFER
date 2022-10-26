#ifndef GEOHISTOGRAM_H
#define GEOHISTOGRAM_H
#include <stdlib.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <math.h>
#include <limits> 
#include <assert.h>
#include <utility>

/*******************************************************************************
Redesign so that it is self-organizing, based on constraints. In all cases, 
bins will be rescaled to avoid overflows, so absolute values are NOT guaranteed.

@@@@ But such rescaling means that older entries contribute less than more
@@@@ recent entries. Especially when testing with simple cases, this factor
@@@@ can grossly skew the distribution: for instance, if we use 16-bit counters
@@@@ and then enter 2^32 elements, the distribution can often reflect that of
@@@@ of the last 2^20 or 2^25 entries, which means you pretty much lose over
@@@@ 90% of the earlier content. With such testing failures, it is hard to 
@@@@ be sure it will work in practice. For now, we should avoid overflows.
@@@@ Eventually, we may want to make CompactFloat as default.

(a) Fix total size, every thing else is automatically determined. Size 
    constraint will limit precision; OR

(b) Fix total size AND number of bins, let the bin-to-bin ratio be determined
    automatically. 

-- two params: NBIN+1, SIZEOFBIN, total can be as small as 64-bits
-- first few bits contains book-keeping info, such as the bin-to-bin factor that 
   will be adjusted when new entries are added. 
-- start with a factor of 2, double the factor as many times as
   needed to ensure that all points will fit within NBINs.
*/
/*******************************************************************************
* Histogram with bins 0 through N-1. 
*   -- Values v < MIN+1 will be put into bin 0. 
*   -- MIN+1 <= v < MIN+FAC will be in bin 1
*   -- MIN+FAC^(n-1) <= v < MIN+FAC^n will be in bin n,
*       or, more simply, FAC^(n-1) <= v-MIN < FAC^n
*   -- v >= MIN + FAC^(N-2) will be in the last bin (N-1)
* where FAC = 2^LOG2FAC
*******************************************************************************
* @@@@ DOES NOT guarantee absolute count values, only the ratio of bin values.
* @@@@ It scales bins down uniformly in order to avoid overflows of largest bins.
*******************************************************************************/

//#define PRESERVE_MEAN_ACCURATELY
//#define PRESERVE_MEAN

#include "HistoStats.h"

template <unsigned N, typename BinType=unsigned, unsigned INCR_BITS=1, 
          int LOG2FAC=1, int MIN=0>
class GeoHistogram {
   typedef GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN> Self;
   static_assert(std::is_unsigned<BinType>(), "Incorrect type for BinType");
   static constexpr BinType ONE = (1u << (INCR_BITS-1));
   static constexpr BinType MAX = (std::numeric_limits<BinType>::max() - ONE);

 private:
   BinType bin_[N];

 public:
   GeoHistogram() { clear();}

   void clear() { for (unsigned i=0; i < N; i++) bin_[i] = 0; }

   unsigned long npoints() const;

   pair<uint8_t, uint8_t> findBin(unsigned long p) const;

   void addPoint(unsigned long p) {
      auto [l, x] = findBin(p);
      bin_[l] += x; if (x != ONE) bin_[l-1] += (ONE-x);
   }

   void addZero(unsigned long count);

   void merge(const Self& other); // Computes the union of the two histograms

   // The following function return a pair (prob, eps) where prob is the 
   // probability that ct is in this histogram, and eps is the estimated
   // error in this probability. This error can be computed on the basis
   // of either the Dvoretzky-Kiefer-Wolfowitz (DKW) inequality or the
   // Chebyshev inequality. 
   ProbRes getProb(unsigned long ct) const;

   void print(std::ostream& os, bool cumulative=false, 
              bool normalize=true) const;

   void serialize(FILE *fp) const {
      unsigned mxbin=0;
      for (unsigned i=0; i < N; i++)
         if (bin_[i] != 0) 
            mxbin = i+1;
      fprintf(fp, "%d ", mxbin);
      for (unsigned i=0; i < mxbin; i++)
         fprintf(fp, "%ld ", (long)bin_[i]);
      fputc('\n', fp);
   }

   void deserialize(FILE* fp) {
      long l; unsigned mxbin;
      assert(fscanf(fp, "%d", &mxbin)==1);      
      for (unsigned i=0; i < mxbin; i++) {
         assert(fscanf(fp, "%ld", &l)==1);
         bin_[i] = (BinType)l;
      }
      for (unsigned i=mxbin; i < N; i++)
         bin_[i] = 0;
   }

 private:
   void addZero1(unsigned long count);
   void compressIfNeeded();
   void compressBins();
   ProbRes probDKW(unsigned long v) const;
   ProbRes probChebyshev(unsigned long v) const;
   ProbRes probGap(unsigned long v) const;
   tuple<float, float, uint8_t> ge(unsigned long ct, bool returnSupprt=0) const;

   void incr(unsigned n, unsigned v = ONE) {
      bin_[n] += v;
      if (bin_[n] >= MAX)
         compressBins();
   }
};

#define GEOHISTOEXTRA_RAW_INCLUDE
#include "GeoHistoExtra.h"
#undef GEOHISTOEXTRA_RAW_INCLUDE

using Histogram =     GeoHistogram<32, unsigned,      1>;
using LongHistogram = GeoHistogram<32, unsigned long, 1>;
#endif
