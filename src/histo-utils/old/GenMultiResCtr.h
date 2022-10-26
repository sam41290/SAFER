#ifndef MULTI_RES_CTR_H
#define MULTI_RES_CTR_H

// @@@@ MultiRestCtr.h is more current, and tested. But the code is a close 
// @@@@ match to this file, so this implementation can be easily revived.
/*******************************************************************************
* Counters can get sophisticated --- for instance, we could maintain n windows,*
* each of duration t, and (efficiently) compute a moving average over a period *
* nt. The average will be updated every t seconds. We can make it even more    *
* sophisticated by adding an exponentially decaying averaging of the counts    *
* preceding the last nt seconds. The combination of flat window of nt plus exp *
* decay of earlier counts can give you something that is closer to using a bell*
* curve for weighted averaging. (See the bottom of this file for an extended   *
* discussion of this complex design.)                                          *
*                                                                              *
*    However, all of this complexity is unnecessary in the context  where we   *
* use counters in the context of anomaly detection. Specifically, we tend to   *
* use them to aggregate events over a period, and then enter them into a       *
* frequency distribution. These frquency distributions will be chained, since  *
* we typically maintain ditributions at multiple time resolutions, e.g., one   *
* counting events per second, next counting events every 4 seconds, then every *
* 16 seconds and so on. We can compute time decaying averages more flexibly by *
* linking the counters maintained with each of these distributions. For        *
* instance, we can look at the simple count over the last 1, 4 and 16 seconds  *
* and compute a more flexible moving average, e.g., c_1 + x*c_4 + y*c_16. This *
* approach gives us a lot more flexibility. At the same time, a simpler counter*
* design will reduce storage requirements as well as runtime.                  *
*                                                                              *
*     In other words, we can get a lot more flexibility by maintaining multiple*
* counters, each of which requires a fraction of the space needed for a more   *
* complex counter that supports windows and exponential averaging. Moreover,   *
* the asymptotic costs for maintain multiple counters is the same as for a     *
* counter. For instance, the counter for 4-second granularity will need to be  *
* updated one fourth as frequently as the 1-second counter.                    *
*                                                                              *
*     Obviously, we could maintain an array of linked counters without         *
* associated  frequency distibutions. All of the points made above regarding   *
* space and time cost will continue to apply in this case as well.             *
*******************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>

using namespace std;

// Counters may be used in multiple ways -- sometimes there is only a 
// single resolution, e.g., when used to support LRU algorithms. Other times,
// e.g., frequency distributions, you need time resolutions that span the
// whole range of possible times. In addition, 16-bit counters may be sufficient
// for infrequent events, but others may need 64-bit counters. So, it is best 
// to leave the full generality offered by the template parameters in this class,
// rather than trying to simplify it further.

template<typename CounterType, int N_RES, int LOG2_TIME_SCALE>
class MultiResCtr {
  static_assert(is_unsigned<CounterType>(), "Incorrect type for CounterType");
 private:
  CounterType count_[2][N_RES];
  unsigned long log2WinSize_:6;
  unsigned long beginTime_: 58;

  static_assert(LOG2_TIME_SCALE >= 1 && LOG2_TIME_SCALE <= 32, 
      "RESOL_FAC must be a power of 2 less than or equal to 2^32");

  // count_[][i] needs to hold larger values for larger values of i. For
  // smaller time scales, we can use smaller number of bits to save on storage.
  // But since events can be bursty, so a factor of N decrease in timescale
  // does not imply a proportionate decrease in counts accumulated at this
  // timescale. Perhaps a reasonable rule of thumb is that we can reduce 
  // counter width by sqrt(N). This means that if we decrease timescale by
  // a factor of 2^48, we can decrease counter widths by 24-bits. For a typical
  // case where the highest level counter is 64-bits, this will contribute
  // an average of 12 bits across the timescales, i.e., less than 20%. If the
  // highest level counter is 32-bits, the timescale won't be larger than 2^32,
  // so avg savings will be 8-bits or 25% --- not worth the increased complexity.
  //
  // So, we skip an optimization that uses different number of bits for counters
  // of different resolution. But we could have a simpler optimization that uses 
  // the same number of bits for all time scales, but allows the bits to be
  // used more efficiently by applying a scale to counts at larger timescales.
  // But this is highly problematic as well --- we could be counting infrequent
  // events, with the result that counts accumulated at a time scale are 
  // often less than this scale factor, causing the promoted counts to become
  // zero after dividing by the scale.

 public:
  static const unsigned CURR=1;
  static const unsigned PREV=0;

  MultiResCtr(unsigned log2WinSize): log2WinSize_(log2WinSize) {
     reset();
  }

  void reset() {
     for (unsigned j=0; j < N_RES; j++) {
        count_[CURR][j] = 0;
        count_[PREV][j] = 0;
        count_[PREV][j]--; // Initialize to -1 to signify it has never been set
     }
     beginTime_ = 0;
  }

  // Returns the window size for the counter at nth resolution
  unsigned long winSize(unsigned n) const {
     assert(n < N_RES);
     return 1ul << (log2WinSize_ + n*LOG2_TIME_SCALE);
  }

  // Returns the begin time for the counter at nth resolution. Note that
  // current count at nth resolution counter includes counts since beginTime(n).
  // However, due to how it is implemented, these counts may not yet
  // have been propagated from count_[CURR][n-1] to count_[CURR][n]. To get
  // the correct value of current count at resolution n, you need to compute:
  //     sum_{i=0}^n count_[CURR][i]

  unsigned long beginTime(unsigned n) const {
     return beginTime_ & (~(winSize(n)-1));
  }

  // Time starts at zero, when the object is created or reset. All increment
  // operations must provide a time that is relative to object creation time.
  // Obviously, time does not need to be related to chronological or wall clock
  // time. It can be logical time, e.g., a counter; the only requirement is
  // that it should not go backwards.

  void inc(unsigned long t, unsigned count=1, void (*f)(void*,unsigned)=0) {
     advance(t, f);
     count_[CURR][0] += count;
  }

  // Projected count is primarily based on PREV count. However, for larger n,
  // PREV count is out of date. Indeed, it may not even have been set once.
  // So, we use a combination of CURR and PREV values to project a count 
  // corresponding to the last winSize(n) seconds.

  CounterType projCount(unsigned n) const {
     assert(n < N_RES);
     CounterType initv = 0; initv--; // PREV cts are set to this val by reset()
     unsigned i=n;
     unsigned long tc = count(n);
     if (i > 0) tc += count(--i);
     if (i > 0) tc += count(--i);
     if (tc == 0 && count_[PREV][n] == initv)
        while (i > 0) 
           tc +=  count(--i);

     unsigned long interval;
     if (i > 0)
        interval = beginTime(i-1) - beginTime(n);
     else interval = beginTime(i) - beginTime(n);
     if (count_[PREV][n] != initv) {
        interval += winSize(n);
        tc += count(n, PREV);
     }
     return ((tc*((winSize(n)<<8)/interval))>>8);
  }

  // Low-level function that returns the raw current value of nth counter. 
  // It is more likely that you are interested in projCount()

  CounterType count(unsigned n, unsigned c=CURR) const {
     assert(n < N_RES);
     return count_[c][n];
  }

  ostream& print(ostream& os=cout) const {
     CounterType initv = 0; initv--; // PREV cts are set to this val by reset()
     for (unsigned i=0; i < N_RES; i++) {
        os << '[';
        if (count_[PREV][i] == initv) 
           os << -1;
        else os << count(i, PREV);
        os << '[' << hex << beginTime(i) 
           << dec << ']' << (long)count(i) << "]\t";
     }
     os << endl;
     return os;
  }

  void advance(unsigned long t, void (*f)(void*, unsigned)=nullptr) {
     unsigned i; unsigned long wsize, begTime;
     for (i=0; i < N_RES; i++) {
        wsize = winSize(i); begTime = beginTime(i);
        if (t - begTime >= wsize) {
           this->promote(i);
           if (f != nullptr) f((void*)this, i);
           // This use of function pointer adds significant overhead, which can
           // be cut by copying advance() code into derived classes
           if (t - begTime < 2*wsize)
              count_[PREV][i] = count_[CURR][i];
                 // Shift count from currrent to previous window
           else count_[PREV][i] = 0;
           count_[CURR][i] = 0;
       }
       else break; // If the window for ith resolution didnt advance, ctr at i+1
    }              // resolution certainly wont advance, so skip more loop iters
    beginTime_ = t;
    beginTime_ = beginTime(0);
  }

 protected:
  const CounterType* countPrevWin() const {
     return count_[PREV];
  };

  void promote(unsigned i) {
     if (i+1 < N_RES) // add counts accumulated at the ith resolution counter
        count_[CURR][i+1] += count_[CURR][i]; // to resolution i+1
  }

};

template<typename CType, int NRES, int LOG2RSFAC>
ostream& operator<<(ostream& os, MultiResCtr<CType, NRES, LOG2RSFAC> c) {
   return c.print(os);
}

#endif
//
// More extensive background on this data structure. Current implementation has 
// been simplified, based on the rationale provided at the top of this file.
//
/******************************************************************************
* 1.Counters: Currently there are two approaches for counting in such a way   *
*   that counts within the past t-seconds contribute much more than the       *
*   counts in the past.                                                       *
*                                                                             *
*   Approach 1: sliding counters. In this case, we simply count the number of *
*   counts within the past w-seconds, ignoring every thing that happened      *
*   earlier. To implement this efficiently, when each new count arrives,      *
*   we need to add it to the total count, and then subtract any counts        *
*   that have now fallen outside of the w-seconds. To illustrate, consider the*
*   following example with w=10. Let the sequence of counts be as shown at    *
*   t=12 and t=17:                                                            *
*                                                                             *
*   t = 12: 0 1 1 2 0 0 1 1 3 2 0 1 (total count in w-seconds: 11)            *
*               |------- w -------|                                           *
*   t = 17: 0 1 1 2 0 0 1 1 3 2 0 1 0 0 0 0 2 (total count in w-seconds: 10)  *
*                       |-------- w --------|                                 *
*                                                                             *
*   As can be seen in the example, 2 new counts happened in the period        *
*   t=13..17, while 3 counts have expired, thus the new count is smaller      *
*   by 1. To implement this algorithm, we need to remember every count        *
*   within the past w-seconds, together with the time these counts were       *
*   seen. If w is large (which can be the case whenever the time resolution   *
*   is sufficiently low), then this requires a lot of storage. To overcome    *
*   this problem, we can use an approximation:                                *
*       -- divide the w-seconds into n-subwindows.                            *
*       -- accumulate counts within each window                               *
*       -- when new count arrives, add the count to the total, and subtract   *
*           the counts belonging to those windows that have expired.          *
*   In effect, this is equivalent to rounding off occurrences of events to    *
*   a time resolution of w/n seconds.                                         *
*                                                                             *
*   A problem with this approach is that regardless of the value of n, the    *
*   count could be off by as much as a factor of 2. For instance, in the      *
*   following example, a max of 200 is happening within w. However, since     *
*   we are rounding off, it is possible that the windows considered will      *
*   never span the two 100-counts, thus the max counted by the rounding       *
*   approach is only 100.                                                     *
*                                                                             *
*   0 100 0 0 ... 0 0 100 0 0                                                 *
*     |--------- w -----|                                                     *
*                                                                             *
*   If storage is not premium, as is the case with freqdistribs, where        *
*   a lot of storage is needed for other things so it does not make sense     *
*   to worry about cunter space, the problem is largely mitigated by using    *
*   sufficiently large n. Although this does not eliminate the problem        *
*   completely, we cannot do any better, since there is always some rounding  *
*   off on time that cannot be eliminated due to factors such as precision    *
*   of the clocks made availble by an OS. If storage is a premium, then       *
*   we should use approach 2, with an exponential decay scheme.               *
*                                                                             *
*   Approach 2:                                                               *
*                                                                             *
*   Use exponential decay so that higher weightage can be given to more       *
*   recent counts. Specifically,                                              *
*                                                                             *
*       T[t] = T[t']*a^(t-t') + C[t]                                          *
*                                                                             *
*   where C[t] denotes the count for the time instance t, T[t] denotes the    *
*   (weighted) total count for the period up to t, t' denotes the last        *
*   time instance preceding t when a non-zero count occurred, and T[t']       *
*   denotes the total weighted count at time t'.                              *
*                                                                             *
*   With this scheme, the question is how one can map the window w of the     *
*   previous approach into the factor a. Suppose that we define w so that     *
*   counts that happened at t-w are given k times (0 < k < 1) as much the     *
*   weightage of counts that occurred at t. Then                              *
*                                                                             *
*       a = exp((ln k)/w)                                                     *
*                                                                             *
*   How rapidly does the count decay? How much weightage is given to past     *
*   counts? This can be calculated by treating T[t] as an infinite series:    *
*                                                                             *
*   T[t] = C[t] + a*C[t-1] + a^2*C[t-2] + a^3*C[t-3] + ....                   *
*                                                                             *
*   To get an idea of the weightage given to past counts as compared to recent*
*   counts, let us assume that the counts are uniform, i.e., C[t'] = c for    *
*   all 0 <= t' <= t. Then,                                                   *
*                                                                             *
*       T[t] = c/(1-a) (holds for any value of t)                             *
*            = T(0, t-w] (i.e., counts contributed by C[1] to C[t-w])         *
*              + T(t-w,t] (i.e., counts from C[t-w+1] to C[t])                *
*            = T[t-w]*a^w + T(t-w, t]                                         *
*            = k*T[t] + T(t-w, t]                                             *
*                                                                             *
*   Thus, counts from 1 thru t-w contribute 100k% to the final count, while   *
*   counts in the window w contribute (1-k)*100%. If we set k = 0.5, then     *
*   we see that 50% of the total count comes from the last w period, 25%      *
*   from the preceding w period, and 25% from all of the time preceding the   *
*   last 2 windows of size w.                                                 *
*                                                                             *
*   Approach 3: A problem with approach 2 is that the decay curve has         *
*   the (exponential decay) form:                                             *
*                                                                             *
*   |                                                                         *
*   |   \                                                                     *
*   |   |                                                                     *
*   |    \                                                                    *
*   |     \                                                                   *
*   |       \                                                                 *
*   |        _                                                                *
*   |         \                                                               *
*   |           ____                                                          *
*   |               \                                                         *
*   |                   _________                                             *
*   |                        \                                                *
*   |                         __________________                              *
*   |                                           \                             *
*   |                                            ___________________________  *
*   |                                                                         *
*   |_________________________________________________________________________*
*                                                                             *
*   More preferable would be a half-bell curve, i.e.,:                        *
*                                                                             *
*   |____ _______                                                             *
*   |            \                                                            *
*   |             |_                                                          *
*   |               \                                                         *
*   |                |                                                        *
*   |                |                                                        *
*   |                |                                                        *
*   |                 \                                                       *
*   |                  |                                                      *
*   |                  |                                                      *
*   |                   \_                                                    *
*   |                      \___                                               *
*   |                         \________                                       *
*   |                                  \____________                          *
*   |                                                \______________________  *
*   |_________________________________________________________________________*
*                                                                             *
*   One possible way to achieve this is by combining approaches 1 and 2.      *
*   Counts during the window w are maintained using approach 1, whereas       *
*   the total count preceding that window is maintained using approach 2.     *
*   We then get the curve:                                                    *
*                                                                             *
*   |__________                                                               *
*   |         |\                                                              *
*   |         | |                                                             *
*   |         |  \                                                            *
*   |         |   \                                                           *
*   |         |    \                                                          *
*   |         |     \_                                                        *
*   |         |       \                                                       *
*   |         |        \_                                                     *
*   |         |          \__                                                  *
*   |         |             \____                                             *
*   |         |                  \________                                    *
*   |         |                           \________________                   *
*   |         |                                            \_________________ *
*   |_________|______________________________________________________________ *
*         w                                                                   *
******************************************************************************/  

