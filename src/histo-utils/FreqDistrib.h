#ifndef FREQ_DISTRIB_H
#define FREQ_DISTRIB_H

#include "Histogram.h"

template <int NUM_HG, class Histo>
class HistogramGrp {
   typedef HistogramGrp<NUM_HG, Histo> Self;
   Histo h_[NUM_HG];

 public:
   HistogramGrp() {};

   HistogramGrp(FILE *fp) {deserialize(fp);};

   const HistogramGrp& operator=(const HistogramGrp& other) {
      for (unsigned i=0; i < NUM_HG; i++)
         h_[i] == other.h_[i];
      return *this;
   }

   bool operator==(const HistogramGrp& other) const {
      for (unsigned i=0; i < NUM_HG; i++)
         if (h_[i] != other.h_[i]) return false;
      return true;
   }
   bool operator!=(const HistogramGrp& oth) const {return !(operator==(oth));}

   static const constexpr unsigned numhg() {return NUM_HG; };

   uint64_t npoints() const { return h_[0].npoints(); };

   void deserialize(FILE *fp) {
      int n;
      assert_abort(fscanf(fp, "%d", &n) == 1);
      for (int i=0; i < n; i++)
         h_[i].deserialize(fp);
      for (int i=n; i < NUM_HG; i++)
         h_[i] = h_[i-1];
   }

   void serialize(FILE *ofp) const {
      int n=NUM_HG-1;
      while (n > 0)
         if (h_[n] == h_[n-1]) 
            n--;
         else break;

      n++;
      fprintf(ofp, "%d\n", n);
      for (int i=0; i < n; i++)
         h_[i].serialize(ofp);
   }

   void merge(const Self& hg) {
      for (int i=0; i < NUM_HG; i++)
         h_[i].merge(hg.h_[i]);
   }

   void addPoint(unsigned scale, typename Histo::ElemType v) 
      {h_[scale].addPoint(v);};
   void addToBinZero(unsigned scale, uint64_t v) {h_[scale].addToBinZero(v);};
   ProbRes getProb(unsigned scale, typename Histo::ElemType v) const {
      return h_[scale].getProb(v);
   };

   ostream& 
   print(ostream& os=cout, bool cumulative=false, bool normalize=false) const {
      for (int i=0; i < NUM_HG; i++)
         h_[i].print(os, cumulative, normalize);
      return os;
   }
};

template <class ElemType>
class EmptyHistoGrp {
 public:
   void addPoint(unsigned scale, ElemType v) {};
   void addToBinZero(unsigned scale, ElemType v) {};
   ostream& print(ostream& os=cout, bool cumulative=false, 
                  bool normalize=false) const {return os;};
};

template 
<class CounterType, class HistoGrp, class Window>
class FreqDistribHelper {

   typedef FreqDistribHelper<CounterType, HistoGrp, Window> Self;

 private:
   HistoGrp hg_;
   unsigned long beginTime_;
   CounterType count_[Window::nwindows];

 public:

   FreqDistribHelper(uint64_t begintm=0) { reset(begintm); };

   unsigned nwin() const { return Window::nwindows; };
   const HistoGrp& hg() const {return hg_; };
   HistoGrp& hg() {return hg_; };

   // Returns the begin time for the counter at nth resolution. Note that
   // current count at nth resolution counter includes counts since beginTime(n).
   // However, due to how it is implemented, these counts may not yet
   // have been propagated from count_[n-1] to count_[n]. To get
   // the correct value of current count at resolution n, you need to compute:
   //     sum_{i=0}^n count_[i]

   unsigned long beginTime(unsigned n) const {
      uint64_t wsize = Window::winsize(n);
      return (beginTime_/wsize)*wsize;
   }

   uint64_t count(unsigned n) const { return count_[n]; };
   void count(unsigned n, uint64_t v) { count_[n] = v;};

   // returns the number of time windows for which counts have changed
   int inc(uint64_t t, unsigned ct) {
      int rv = 1;
      if (t - beginTime_ >= Window::winsize(0)) {
         assert_abort(t >= beginTime_);
         rv=advance(t);
      };
      count_[0] += ct;
      return rv;
   };

   // Returns the number of time windows for which counts have changed. We have
   // inlined one iteration of the body of advance here. This gives far better
   // performance when the smallest time window is small, e.g., 1. Substantial
   // performance edge persists even at 16, say, 70%. It disappears at 256, or
   // turns the other way around, but the performance at that point is so good
   // that it does not matter. For the optimization to work well, advance()
   // should not be inlined.
   int inc(uint64_t t) {
      int rv = 1;
      auto wsize0 = Window::winsize(0);
      if (t - beginTime_ >= wsize0) {
         assert_abort(t >= beginTime_);
         count_[1] += (uint64_t)count_[0];
         hg_.addPoint(0, count_[0]);
         count_[0] = 0;
         if (t - beginTime_ >= 2*wsize0) 
            hg_.addToBinZero(0, (t-beginTime_)/wsize0-1);
         rv++;
         if (t-beginTime(1) >= Window::winsize(1))
            rv=advance(t, 1);
         else {
            beginTime_ = t;
            beginTime_ = beginTime(0);
         }
      };
      ++count_[0];
      return rv;
   };

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

   void finalize(uint64_t t) {
      for (int i=0; i < Window::nwindows; i++) {
         uint64_t begintime = beginTime(i), wsize = Window::winsize(i);
         if (i+1 < Window::nwindows)
            count(i+1, count(i+1)+count(i));
         hg_.addPoint(i, count(i));
         count(i, 0);
         if (t - begintime >= 2*wsize)
            hg_.addToBinZero(i, (t-begintime)/wsize-1);
      }
      beginTime_ = t;
      beginTime_ = beginTime(0);
   }

/*   
   void finalize(uint64_t ts) {
      // First, advance all timewindows to reach current time
      inc(ts, 0); 

      // Now, propagate any remaining count to higher time windows. Note that
      // when a count is propagated upwards in the previous step, that count 
      // is reset in inc() and advance(). So, finalize won't double count them;
      // Instead, it will only promote remaining counts from time windows that
      // have not ended by the time ts.
      unsigned long remCount = 0;
      for (unsigned i=0; i < Window::nwindows; i++) {
         remCount += count(i);
         if (remCount > 0) {
            count(i, remCount);
            hg_.addPoint(i, remCount);
         }
      }
   }
*/

   ostream& print(ostream& os=cout, bool cumulative=false, 
                  bool normalize=false) {
      for (unsigned i=0; i < Window::nwindows; i++) {
         os << '[';
         os << '[' << hex << beginTime(i) 
            << dec << ']' << (long)count(i) << "]\t";
      }
      os << endl;
      hg_.print(os, cumulative, normalize);
      return os;
   }

 private:
  
   int __attribute__ ((noinline)) advance(unsigned long t, int j=0) {
      int rv=0;
      for (int i=j; i < Window::nwindows; i++) {
         rv = i+1;
         uint64_t begintime = beginTime(i), wsize = Window::winsize(i);
         if (t - begintime >= wsize) {
            if (i+1 < Window::nwindows)
               count(i+1, count(i+1)+count(i));
            hg_.addPoint(i, count(i));
            count(i, 0);
            if (t - begintime >= 2*wsize)
               hg_.addToBinZero(i, (t-begintime)/wsize-1);
         }
         else break;
      }
      beginTime_ = t;
      beginTime_ = beginTime(0);

      return rv;
   }

   void reset(unsigned long begtime) {
      beginTime_ = begtime;
      beginTime_ = beginTime(0);

      if constexpr (is_arithmetic_v<CounterType>) {
         for (unsigned j=0; j < Window::nwindows; j++)
            count_[j] = 0;
      }
   }
};

template 
<class CounterType, class HistoGrp, class Window>
inline ostream& operator<<(ostream& os, 
    const FreqDistribHelper<CounterType, HistoGrp, Window>& c) {
   return c.print(os);
}

/************ Example Window Classes for Instantiating FreqDistrib ************/
template <unsigned WIN0LEN, unsigned long WIN_RATIO, unsigned N_WIN>
struct SimpleTimeWindows {
   struct InitHelper { // To initialize array at compile time without errors
      static constexpr auto computeWindows() {
         std::array<uint64_t, N_WIN> rv = {WIN0LEN};
         for (unsigned i=1; i < N_WIN; i++)
            rv[i] = rv[i-1]*WIN_RATIO;
         return rv;
      };
   };

   inline static const int nwindows = N_WIN;
   inline static const constexpr auto windows=InitHelper::computeWindows();
   inline static constexpr uint64_t winsize(unsigned i) {
      assert_fix(i < N_WIN, i=N_WIN-1);
      return windows[i];
   };
};

template <uint64_t... WINSIZES>
struct AltSimpleTimeWindows {
   inline static const constexpr uint64_t windows[] = {WINSIZES...};
   inline static const int nwindows = sizeof(windows)/8;
   inline static constexpr uint64_t winsize(unsigned i) {
      assert_fix(i < nwindows, i=nwindows-1);
      return windows[i];
   };
};

// A more complex window class can be defined to follow time periods such as
// months that have varying lengths. We may prefer to use hour/day/week/month as
// time windows because they match periodic activities in an enterprise. In such
// a case, the sizes of windows is not a constant, e.g., months have differing
// number of days. Variable length is relatively easy to handle: we can avoid
// the use of a constant array windows[], and instead define winsize() to be a
// function that returns the correct info for the current month. But a more
// complex issue is that successive time windows may not be integral multiples
// (e.g., weeks and months). Note that FrequencyDistrib class above propagates
// count from lower to higher window only when the lower window ends. This means
// that propagation will be delayed, so one month's count may include the counts
// of 5 weeks, including the partial week at the beginning of the next week.
// This also means that the next month may contain just 4 weeks. This
// variability can defeat the whole purpose of such time windows, namely, to
// model periodic actitivies. Addressing this requires changes to FreqDistrib
// class, so that (a) promotion can happen even before the end of current
// window, and (b) counts within any time window are maintained split into two
// components, one that has been promoted and another that hasn't been.

/********** Partially configured FreqDistrib Classes Ready for Use ***********/
template<unsigned N_WIN>
using FreqDistribHistoGrp = HistogramGrp<N_WIN, GeoHistogramNU<0, 11, 6, 2>>;
// NOTE: GeoHistogramNU<0,11,6,2> will have 20 bins covering 2^48:
// 0 1-3 4-15 16-63 64-255 256-1K 1K-4K 4K-16K 16K-64K 64K-256K 256K-1M 1M-4M
// 4M-32M 32M-256M 256M-2B 2B-16B 16B-128B 128B-1T 1T-16T 16T-256T.
// An alternative setting is <3, 8, 5, 3>, also with 20 bins but 2^46 range.
// 0 1 2-3 4-7 8-31 32-127 128-511 512-2K 2K-8K 8K-32K 32K-128K 128K-512K
// 512K-4M 4M-32M 32M-256M 256M-2B 2B-16B 16B-256B 256B-4T 4T-64T.

template <unsigned WIN0LEN, unsigned WIN_RATIO, unsigned N_WIN>
using FreqDistribLearn = 
   FreqDistribHelper<CompactCounter<uint32_t, 26, 6>, 
                     FreqDistribHistoGrp<N_WIN>,
                     SimpleTimeWindows<WIN0LEN, WIN_RATIO, N_WIN>>;

template <unsigned WIN0LEN, unsigned WIN_RATIO, unsigned N_WIN>
using FreqDistribDetect = 
   FreqDistribHelper<CompactCounter<uint32_t, 26, 6>, 
                     EmptyHistoGrp<CompactCounter<uint32_t, 26, 6>>,
                     SimpleTimeWindows<WIN0LEN, WIN_RATIO, N_WIN>>;

template <uint64_t... WINSIZES>
using FreqDistribLearnAlt = 
   FreqDistribHelper<CompactCounter<uint32_t, 26, 6>, 
                     HistogramGrp<AltSimpleTimeWindows<WINSIZES...>::nwindows,
                                  GeoHistogramNU<0, 11, 6, 2>>,
                     AltSimpleTimeWindows<WINSIZES...>>;
template <uint64_t... WINSIZES>
using FreqDistribDetectAlt = 
   FreqDistribHelper<CompactCounter<uint32_t, 26, 6>, 
                     EmptyHistoGrp<CompactCounter<uint32_t, 26, 6>>,
                     AltSimpleTimeWindows<WINSIZES...>>;
/*
template <unsigned WIN0LEN, unsigned WIN_RATIO, unsigned N_WIN>
using FreqDistribLearn = 
   FreqDistribHelper<unsigned,
                     FreqDistribHistoGrp<N_WIN>,
                     SimpleTimeWindows<WIN0LEN, WIN_RATIO, N_WIN>>;

template <unsigned WIN0LEN, unsigned WIN_RATIO, unsigned N_WIN>
using FreqDistribDetect = 
   FreqDistribHelper<unsigned,
                     EmptyHistoGrp<unsigned>,
                     SimpleTimeWindows<WIN0LEN, WIN_RATIO, N_WIN>>;

template <uint64_t... WINSIZES>
using FreqDistribLearnAlt = 
   FreqDistribHelper<unsigned, 
                     HistogramGrp<AltSimpleTimeWindows<WINSIZES...>::nwindows,
                                  GeoHistogramNU<0, 11, 6, 2>>,
                     AltSimpleTimeWindows<WINSIZES...>>;
template <uint64_t... WINSIZES>
using FreqDistribDetectAlt = 
   FreqDistribHelper<unsigned,
                     EmptyHistoGrp<unsigned>,
                     AltSimpleTimeWindows<WINSIZES...>>;
*/

#endif
