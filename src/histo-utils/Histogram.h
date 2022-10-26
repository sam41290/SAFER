#ifndef HISTOGRAM_H
#define HISTOGRAM_H

using namespace std;

#include "CompactCounter.h"
#include "HistoStats.h"

/*******************************************************************************
* Histograms take the following template parameters: 
*
*   -- N: the number of bins. 
*
*   -- ElemType: a numeric type that denotes the type of elements in the 
*      Histogram. It affects neither the size nor the performance of Histograms
*      so it is best to use long, uint64_t, or double.
*
*   -- BinType: The representation of each bin. Storage-wise, Histograms are 
*      just an array[N] of BinType. Best to leave BinType to be the default
*      choice. However, if no precision loss is tolerable, BinType should be
*      specified as uint64_t; or, if counts can go beyond 2^64, specify BinType
*      as double.
*
*   -- Binner: a class that specifies how elements are grouped into bins. It 
*      should provide two static functions:
*        -- bin(ElemType) -> unsigned that mapping a value to a bin number, and
*        -- start(unsigned i) -> ElemType that gives the smallest value in bin i.
*      Specifically:
*        -- bin i holds values v such that binstart(i) <= v < binstart(i-1)
*      So the following invariant should hold for these two functions:
*        -- binstart(bin(n)) <= n < binstart(bin(n)+1)
*      We can't track the high end of the last bin, so everything greater than
*      or equal to binstart(N-1) will go there. 
*
* This Histogram class is very flexible but needs significant work to set up. In
* particular, we need to define a Binner class. This is done in HistoBinner.h.
* Several easy-to-setup histogram types are also defined in that header file.
*******************************************************************************/

// @@@@ Typically, the number of histogram bins is large (20?), but only some of
// @@@@ them will be nonempty. Add maxnzbin (and possibly minnzbin) to speed up
// @@@@ Histogram computations. This seems easy to do.

template <class Binner, class ElemTp=uint64_t, 
          class BinType=CompactCounter<uint32_t, 26, 6>>
class Histogram {
   typedef Histogram<Binner, ElemTp, BinType> Self;
 private:
   BinType bin_[Binner::nbins()];

 public:
   typedef ElemTp ElemType;

   Histogram() { if constexpr (is_arithmetic_v<BinType>) clear(); };
   Histogram(const Histogram& other) { *this = other;};

   const Histogram& operator=(const Histogram& other) {
      for (unsigned i=0; i < Binner::nbins(); i++) 
         bin_[i] = other.bin_[i];
      return *this;
   }
   bool operator==(const Histogram& other) const {
      for (unsigned i=0; i < Binner::nbins(); i++) 
         if (bin_[i] != other.bin_[i]) return false;
      return true;
   }
   bool operator!=(const Histogram& other) const {return !(operator==(other));}

   void clear() { for (unsigned i=0; i < Binner::nbins(); i++) bin_[i] = 0; }

   uint64_t npoints() const;

   void addPoint(ElemTp p) { ++bin_[Binner::bin(p)]; };
   void addPoint(ElemTp p, unsigned ct) { bin_[Binner::bin(p)] += ct; }
   void rmPoint(ElemTp p, unsigned ct) { bin_[Binner::bin(p)] -= ct; }

   void addToBinZero(uint64_t count) { bin_[0] += count;};

   void merge(const Self& other); // Computes the union of the two histograms

   // The following function return a pair (prob, eps) where prob is the 
   // probability that ct is in this histogram, and eps is the estimated
   // error in this probability. This error can be computed on the basis
   // of either the Dvoretzky-Kiefer-Wolfowitz (DKW) inequality or the
   // Chebyshev inequality. 
   ProbRes getProb(ElemTp ct) const;

   void print(std::ostream& os, bool cumulative=false, 
              bool normalize=true) const;

   void serialize(FILE *fp) const {
      unsigned mxbin=0;
      for (unsigned i=0; i < Binner::nbins(); i++)
         if (bin_[i] != 0) 
            mxbin = i+1;
      fprintf(fp, "%d ", mxbin);
      for (unsigned i=0; i < mxbin; i++)
         fprintf(fp, "%lu ", (uint64_t)bin_[i]);
      fputc('\n', fp);
   }

   void deserialize(FILE* fp) {
      uint64_t l; unsigned mxbin;
      assert_abort(fscanf(fp, "%d", &mxbin)==1);      
      for (unsigned i=0; i < mxbin; i++) {
         assert_abort(fscanf(fp, "%lu", &l)==1);
         bin_[i] = l;
      }
      for (unsigned i=mxbin; i < Binner::nbins(); i++)
         bin_[i] = 0;
   }

 private:
   ProbRes probDKW(ElemTp v) const;
   ProbRes probChebyshev(ElemTp v) const;
   ProbRes probGap(ElemTp v) const;
   tuple<double, double, double> ge(ElemTp v, bool returnSupprt=0) const;
};

#include "HistoExtra.h"
#include "HistoBinner.h"

template <class Binner, class ElemTp, class BinTp>
ostream& operator<<(ostream& os, const Histogram<Binner, ElemTp, BinTp>& h) {
   h.print(os); return os;
};

#endif
