#ifndef FREQ_DISTRIB_RAW_INCLUDE
static_assert(false, "Don't include this header file directly");
#endif

#ifndef HISTOGRAM_GRP_H
#define HISTOGRAM_GRP_H

#include "GeoHistogram.h"

//
// @@@@ FreqDistrib is designed to be space and time efficient without needing
// @@@@ much configuration. But two facts to note: it is fairly large (about
// @@@@ 1KB now), and shares the overflow issues of MultiResSlidingCtr and 
// @@@@ GeoHistogram. (It was smaller before, but there was more risk of
// @@@@ overflows; now there is no risk for rates < 4 events/ns, and if
// @@@@ the clock granularity is no coarser than 10ms.)
//
// @@@@ Redesign with params: params of redesigned MultiResSlidingCtr + :
// @@@@ h0 should have as many bins as needed to hold the max value of minresctr
// @@@@ h1 should be able to hold (2**log2fac_) times h0_ value, and so on.

struct HistogramGrp {
   GeoHistogram< 12, unsigned, 1, 2, 0> h00_; // Window of size 0
   GeoHistogram< 12, unsigned, 1, 2, 0> h0_;
   GeoHistogram< 14, unsigned, 1, 2, 0> h1_;
   GeoHistogram< 16, unsigned, 1, 2, 0> h2_;
   GeoHistogram< 18, unsigned, 1, 2, 0> h3_;
   GeoHistogram< 20, unsigned, 1, 2, 0> h4_;
   GeoHistogram< 22, unsigned, 1, 2, 0> h5_;
   GeoHistogram< 22, unsigned, 1, 2, 0> h6_;
   GeoHistogram< 24, unsigned, 1, 2, 0> h7_;
   GeoHistogram< 24, unsigned, 1, 2, 0> h8_;
   GeoHistogram< 26, unsigned, 1, 2, 0> h9_;

   HistogramGrp() {};

   HistogramGrp(FILE *fp) {deserialize(fp);};

   unsigned long npoints() const { return h00_.npoints(); };

   void deserialize(FILE *fp) {
      h00_.deserialize(fp);
      h0_.deserialize(fp);
      h1_.deserialize(fp);
      h2_.deserialize(fp);
      h3_.deserialize(fp);
      h4_.deserialize(fp);
      h5_.deserialize(fp);
      h6_.deserialize(fp);
      h7_.deserialize(fp);
      h8_.deserialize(fp);
      h9_.deserialize(fp);
   }

   void serialize(FILE *ofp) const {
      h00_.serialize(ofp);
      h0_.serialize(ofp);
      h1_.serialize(ofp);
      h2_.serialize(ofp);
      h3_.serialize(ofp);
      h4_.serialize(ofp);
      h5_.serialize(ofp);
      h6_.serialize(ofp);
      h7_.serialize(ofp);
      h8_.serialize(ofp);
      h9_.serialize(ofp);
   }

   ostream& __attribute__ ((noinline)) 
   print(ostream& os=cout, bool cumulative=false, bool normalize=false) const {
      h00_.print(os, cumulative, normalize);
      h0_.print(os, cumulative, normalize);
      h1_.print(os, cumulative, normalize);
      h2_.print(os, cumulative, normalize);
      h3_.print(os, cumulative, normalize);
      h4_.print(os, cumulative, normalize);
      h5_.print(os, cumulative, normalize);
      h6_.print(os, cumulative, normalize);
      h7_.print(os, cumulative, normalize);
      h8_.print(os, cumulative, normalize);
      h9_.print(os, cumulative, normalize);
      return os;
   }

   void __attribute__ ((noinline)) addPointl(unsigned i, unsigned long v) {
      switch (i) {
         case 0: return h00_.addPoint(v);
         case 1: return h0_.addPoint(v);
         case 2: return h1_.addPoint(v);
         case 3: return h2_.addPoint(v);
         case 4: return h3_.addPoint(v);
         case 5: return h4_.addPoint(v);
         case 6: return h5_.addPoint(v);
         case 7: return h6_.addPoint(v);
         case 8: return h7_.addPoint(v);
         case 9: return h8_.addPoint(v);
         case 10: return h9_.addPoint(v);
         default: assert(false);
      }
   }

   void __attribute__ ((noinline)) addzl(unsigned i, unsigned long v) {
      switch (i) {
         case 0: return h00_.addZero(v);
         case 1: return h0_.addZero(v);
         case 2: return h1_.addZero(v);
         case 3: return h2_.addZero(v);
         case 4: return h3_.addZero(v);
         case 5: return h4_.addZero(v);
         case 6: return h5_.addZero(v);
         case 7: return h6_.addZero(v);
         case 8: return h7_.addZero(v);
         case 9: return h8_.addZero(v);
         case 10: return h9_.addZero(v);
         default: assert(false);
      }
   }

   ProbRes __attribute__ ((noinline)) getProb(unsigned scale, int bin) const {
      switch (scale) {
         case 0: return h00_.getProb(bin);
         case 1: return h0_.getProb(bin);
         case 2: return h1_.getProb(bin);
         case 3: return h2_.getProb(bin);
         case 4: return h3_.getProb(bin);
         case 5: return h4_.getProb(bin);
         case 6: return h5_.getProb(bin);
         case 7: return h6_.getProb(bin);
         case 8: return h7_.getProb(bin);
         case 9: return h8_.getProb(bin);
         case 10: return h9_.getProb(bin);
         default: assert(false);
      }
   }

   void merge(const HistogramGrp& hg) {
      h00_.merge(hg.h00_);
      h0_.merge(hg.h0_);
      h1_.merge(hg.h1_);
      h2_.merge(hg.h2_);
      h3_.merge(hg.h3_);
      h4_.merge(hg.h4_);
      h5_.merge(hg.h5_);
      h6_.merge(hg.h6_);
      h7_.merge(hg.h7_);
      h8_.merge(hg.h8_);
      h9_.merge(hg.h9_);
   }
};
#endif

class FreqDistrib {

 private:
  static const unsigned LOG2_TIME_SCALE=4;
  static const unsigned CURR=1;
  static const unsigned PREV=0;

  unsigned char log2Win1Size_;   // 
  unsigned long beginTime_: 56;
  unsigned long lastts_; // Last tick when inc() was called on us. 
  unsigned int count0_;  // Window w0 of size zero, stores #inc's this tick
  unsigned int count1_[2][3];   // count1_[][1] is size w1 = baseWinSize(). Next
  unsigned long count2_[2][7];  // counters incr. win size by f = 2^log2Win1Size_.

  // count_[][i] needs to hold larger values for larger values of i. For
  // smaller time scales, we can use smaller number of bits to save on storage.
  // But since events can be bursty, so a factor of N decrease in timescale
  // does not imply a proportionate decrease in counts accumulated at this
  // timescale. Perhaps a reasonable rule of thumb is that we can reduce 
  // counter width by sqrt(N). By this rule, the lowest granularity is
  // 

#ifdef LEARN_MODE
  HistogramGrp hg_;
#define addPoint(a, b) hg_.a.addPoint(b)
#define addPointl(a, b) hg_.addPointl(a, b)
#define addZero(a, b)  hg_.a.addZero(b)
#define addzl(a, b)    hg_.addzl(a, b)
#else
#define addPoint(a, b)
#define addPointl(a, b)
#define addZero(a, b)
#define addzl(a, b)
#endif

 public:
   FreqDistrib() {
      reset(0, 8);
   }
      
   FreqDistrib(unsigned long begintm, unsigned char log2Win1Size) {
      reset(begintm, log2Win1Size);
   }

   unsigned long w0size() const { return 0; };
   unsigned long baseWinSize() const { return 1ul << log2Win1Size_; };
   unsigned long w1size() const { return baseWinSize(); };
   unsigned long winSize(unsigned n) const {
      if (n == 0) return 0;
      assert(--n < 10);
      return 1ul << (log2Win1Size_ + n*LOG2_TIME_SCALE);
   }

   // Returns the begin time for the counter at nth resolution. Note that
   // current count at nth resolution counter includes counts since beginTime(n).
   // However, due to how it is implemented, these counts may not yet
   // have been propagated from count_[CURR][n-1] to count_[CURR][n]. To get
   // the correct value of current count at resolution n, you need to compute:
   //     sum_{i=0}^n count_[CURR][i]

   unsigned long beginTime(unsigned n) const {
      if (n==0) return lastts_;
      return beginTime_ & (~(winSize(n)-1));
   }

   unsigned long count(unsigned n, unsigned c=CURR) const {
      if (n-- == 0)
         return count0_; // Confusing that there is no CURR or PREV.
                         // Should get rid of sliding counter design.
      if (n < 3)
         return count1_[c][n];
      else if (n < 10)
         return count2_[c][n-3];
      else assert(false);
   }

   void count(unsigned n, unsigned c, unsigned long v) {
      if (n-- == 0)
         count0_ = v;

      if (n < 3)
         count1_[c][n] = v;
      else if (n < 10)
         count2_[c][n-3] = v;
      else assert(false);
   }

   // returns the number of time windows for which counts have changed
   int inc(unsigned long t, unsigned ct=1) {
     if (t == lastts_) {
        count0_ += ct;
        return 1;
     }
     else {
        int rv = 2;
        if (count0_ != 0) // h00_ never has zero counts
           addPoint(h00_, count0_);
        count1_[CURR][0] += count0_;
        count0_ = ct;

        if (t - beginTime_ >= baseWinSize()) {
#ifdef DEBUG
           cout << "Advancing t=" << t << " begintime=" << beginTime_ << endl;
#endif
           rv = advance(t);
        }
        lastts_ = t;
        return rv;
     }
   }

   // Recall that we propagate counts from a lower to the next higher time
   // window at the *end* of the higher window. This means that most counters at
   // the higher end are zero because we have not seen the end of even a single
   // one of those larger time wondows. This function should be called to force
   // propagation. But this early promotion will cause double-counting later on,
   // so forcing can be done only at the end; hence the name finalize. 
   //
   // The ts argument should correspond to the last time at which an event
   // relevant to this distribution took place. We want to first advance to this
   // ts so that the correct number of addz's will be done. Then we finalize to
   // to propagate counts.
   
   void finalize(uint64_t ts) {
      // First, advance all timewindows to reach current time
      inc(ts, 0); 

      // Now, propagate any remaining count to higher time windows. Note that
      // when a count ia propagated upwards in the previous step, that count 
      // is reset in inc() and advance(). So, finalize won't double count them;
      // Instead, it will only promote remaining counts from time windows that
      // have not ended by the time ts.
      unsigned long remCount = count(0);
      for (unsigned i=1; i < 11; i++) {
         remCount += count(i);
         if (remCount > 0) {
            count(i, CURR, remCount);
            addPointl(i, remCount);
         }
      }
   }

   ostream& print(ostream& os=cout, bool cumulative=false, 
                  bool normalize=false) {
      os << "[[" << lastts_ << "] " << count0_ << "]\t";
      for (unsigned i=1; i < 11; i++) {
         os << '[';
         if (isInit(i)) 
            os << -1;
         else os << count(i, PREV);
         os << '[' << hex << beginTime(i) 
            << dec << ']' << (long)count(i) << "]\t";
      }
      os << endl;
#ifdef LEARN_MODE
      hg_.print(os, cumulative, normalize);
#endif
      return os;
   }

#ifdef LEARN_MODE
   const HistogramGrp& hg() const { return hg_; };
#endif

 private:
  
   int advance(unsigned long t) {
      int rv=2;
      unsigned long wsize = baseWinSize();
      // Enter count into histogram. Also accumulate count into next window 
      addPoint(h0_, count1_[CURR][0]);
      count1_[CURR][1] += count1_[CURR][0];

      // Shift count from currrent to previous window
      if (t - beginTime_ < 2*wsize)
         count1_[PREV][0] = count1_[CURR][0];
      else {
         count1_[PREV][0] = 0;
         addZero(h0_, ((t-beginTime_)/wsize)-1);
      }
      count1_[CURR][0] = 0;

      if (t - beginTime(2) >= winSize(2))
         rv = advance1(t);

      beginTime_ = t;
      beginTime_ = beginTime(1);
      return rv;
   }

   // Code below duplicates advance() code, but is a performance optimization.
   // At some point, we found out that the compiler aggressively inlines the
   // whole function, and this causes reduced performance in this case. Not sure
   // that this holds still --- at least on testFD.C on 1/21/21, there is no
   // difference if we remove this attribute. 

   int /*__attribute__ ((noinline))*/ advance1(unsigned long t) {
     unsigned i; unsigned long wsize, begTime; 
     for (i=2; i < 11; i++) {
        wsize = winSize(i); begTime = beginTime(i);
        if (t - begTime >= wsize) {
           addPointl(i, count(i)); // Enter count into histogram. 
           if (i+1 < 11)// Add counts accumulated at the ith resolution counter
              count(i+1, CURR, count(i+1) + count(i)); // to resolution i+1.

           // Shift count from current to previous window
           if (t - begTime < 2*wsize)
              count(i, PREV, count(i));
           else {
              count(i, PREV, 0); // Many windows with zero counts have passed, so
              addzl(i, ((t-begTime)/wsize)-1); // update histogrm w/ 0 counts
           }
           count(i, CURR, 0);
        }
        else return i; // If the window for ith resolution didnt advance, ctr at
     }         // i+1 resolution certainly wont advance, so skip more loop iters
     return 11;
   }

   void reset(unsigned long begtime, unsigned log2Win1Size) {
      assert(log2Win1Size < 20); // Higher values don't make sense for this impl.
      log2Win1Size_ = log2Win1Size;
      lastts_ = begtime;
      beginTime_ = begtime;
      beginTime_ = beginTime(1);

      count0_ = 0;
      for (unsigned j=1; j < 11; j++) {
         count(j, CURR, 0);
         count(j, PREV, ~0ul);
      }
   }

   bool isInit(unsigned n) const {
      if (n-- == 0) return false;

      if (n < 3)
         return (count1_[PREV][n] == ~0u);
      else if (n < 10)
         return (count2_[PREV][n-3] == ~0ul);
      else assert(false);
   }

};

inline ostream& operator<<(ostream& os, FreqDistrib c) {
   return c.print(os);
}

#undef addPoint
#undef addPointl
#undef addZero
#undef addzl


