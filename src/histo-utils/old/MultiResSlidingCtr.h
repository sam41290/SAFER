#ifndef MULTI_RES_SLIDING_CTR_H
#define MULTI_RES_SLIDING_CTR_H

// @@@@ NOTE: ALL CODE FROM THIS FILE MOVED INTO FREQDISTRIB. 

/*******************************************************************************
*   This class supports sliding windows for each counter, plus multiple       *
*   counters that operate at window sizes that increase by a factor. The goal *
*   of a sliding window is to have the count over past w-seconds, ignoring    *
*   every thing that happened earlier. To implement this efficiently, when    *
*   each new count arrives, we need to add it to the total count, and then    *
*   subtract any counts that have now fallen outside of the w-seconds. To     *
*   illustrate, consider the following example with w=10. Let the sequence of *
*   counts be as shown at t=12 and t=17:                                      *
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
*   While the worst case error is 2x, the probability of this error decreases *
*   exponentially with n. [A count of k can be distributed among n bins in    *
*   (k+n-1 choose n-1) ways, which is about O(k^n)]                           *
*                                                                             *
*   In the design below, we have set n=2, which the same worst-case but much  *
*   higher average case error. Still, it probably is not worth the added      *
*   complexity to the logic that is introduced by sliding wondows.            *
*/
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
* frequency distribution. These frequency distributions will be chained, since  *
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
#include <bitset>

using namespace std;

// Counters may be used in multiple ways -- sometimes there is only a 
// single resolution, e.g., when used to support LRU algorithms. Other times,
// e.g., frequency distributions, you need time resolutions that span the
// whole range of possible times. We specialize for the latter case, using
// sensible default values and space optimization techniques so that the
// class can be used without thinking too much about how to configure the
// number of windows, counter widths, etc.

//
// @@@@ To avoid overflow, CALLER MUST ENSURE that counts per (1<<2*log2WinSize_)
// @@@@ is less than 65K. Note that if you set log2WinSize_ to its default and 
// @@@@ time is in ns, this translates to a max rate of 256 per ns. At this 
// @@@@ rate, counts are maintained for intervals of 16ns, 256ns, ..., 1100s.
//

class MultiResSlidingCtr {
 protected:
  static const unsigned LOG2_TIME_SCALE=4;

  unsigned long lastts_;
  unsigned char log2WinSize_;   // 
  unsigned long beginTime_: 56; // Last tick when inc() was called on us.
  unsigned int count0_; // Window w0 of size zero, stores #inc's this tick
  unsigned int count1_[2][3];   // count1_[][1] is size w1 = baseWinSize(). Next
  unsigned long count2_[2][7];  // counters incr. win size by f = 2^log2WinSize_.

  // count_[][i] needs to hold larger values for larger values of i. For
  // smaller time scales, we can use smaller number of bits to save on storage.
  // But since events can be bursty, so a factor of N decrease in timescale
  // does not imply a proportionate decrease in counts accumulated at this
  // timescale. Perhaps a reasonable rule of thumb is that we can reduce 
  // counter width by sqrt(N). By this rule, the lowest granularity is
  // 

 public:
  static const unsigned CURR=1;
  static const unsigned PREV=0;

  MultiResSlidingCtr(unsigned log2WinSize=8): log2WinSize_(log2WinSize) {
     assert(log2WinSize_ < 20); // Higher values don't make sense for this impl.
     reset(0);
  }

  MultiResSlidingCtr(unsigned long beginTime, 
                     unsigned log2WinSize): log2WinSize_(log2WinSize) {
     assert(log2WinSize_ < 20); // Higher values don't make sense for this impl.
     reset(beginTime);
  }

  unsigned long w0size() const { return 0; };
  unsigned long baseWinSize() const { return 1ul << log2WinSize_; };
  unsigned long w1size() const { return baseWinSize(); };
  unsigned long winSize(unsigned n) const {
     if (n == 0) return 0;
     assert(--n < 10);
     return 1ul << (log2WinSize_ + n*LOG2_TIME_SCALE);
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

  void reset(unsigned long begtime) {
     lastts_ = begtime;
     beginTime_ = begtime;
     count0_ = 0;
     for (unsigned j=1; j < 11; j++) {
        count(j, CURR, 0);
        count(j, PREV, ~0ul);
     }
  }

  // Low-level function that returns the raw current value of nth counter. 
  // It is more likely that you are interested in projCount()

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

  bool isInit(unsigned n) const {
     if (n-- == 0) return false;

     if (n < 3)
        return (count1_[PREV][n] == ~0u);
     else if (n < 10)
        return (count2_[PREV][n-3] == ~0ul);
     else assert(false);
  }

  ostream& print(ostream& os=cout) const {
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
     return os;
  }

  // All increment operations must provide a time. Obviously, time does not need
  // to be related to chronological or wall clock time. It can be logical time,
  // e.g., a counter; the only requirement is that it should not go backwards.
  // There are also some constraints to prevent overflow.

  int inc(unsigned long t, unsigned ct) {
     if (t == lastts_) {
        count0_ += ct;
        return 1;
     }
     else {
        // Accumulate count into next window 
        int rv = 2;
        count1_[CURR][0] += count0_;
        count0_ = ct;

        if (t - beginTime_ >= baseWinSize())
           rv = advance(t);

        lastts_ = t; 
        return rv;
     }
  };

 private:

   int advance(unsigned long t) {
      int rv=2;
      count1_[CURR][1] += count1_[CURR][0];

      // Shift count from currrent to previous window
      if (t - beginTime_ < 2*baseWinSize())
         count1_[PREV][0] = count1_[CURR][0];
      else count1_[PREV][0] = 0;
      count1_[CURR][0] = 0;

      if (t - beginTime(2) >= winSize(2))
         rv = advance1(t);

      beginTime_ = t;
      beginTime_ = beginTime(1);
      return rv;
   }

   int __attribute__ ((noinline)) advance1(unsigned long t) {
     unsigned i; unsigned long wsize, begTime; 
     for (i=2; i < 11; i++) {
        wsize = winSize(i); begTime = beginTime(i);
        if (t - begTime >= wsize) {
           if (i+1 < 11)// Add counts accumulated at the ith resolution counter
              count(i+1, CURR, count(i+1) + count(i)); // to resolution i+1.

           // Shift count from current to previous window
           if (t - begTime < 2*wsize)
              count(i, PREV, count(i));
           else count(i, PREV, 0);
           count(i, CURR, 0);
        }
        else return i; // If the window for ith resolution didnt advance, ctr at
     }         // i+1 resolution certainly wont advance, so skip more loop iters
     return 11;
   }

/****************************************************************************** 
   No good use for this function yet. We can uncomment is there is a need.
   At that point, we should fix it so that the contribution from CURR and
   PREV window is proportional to how much of the current window overlaps
   with either of these two.
*******************************************************************************

  unsigned long projCount(unsigned n) const {

    // The basic approach is to add CURR and PREV count. This count has been
    // accumulated over the interval that includes the entire prev window plus
    // the partial current window. So we do a linear extrapolation: multiply
    // PREV+CURR by windowsize/interval. This simple approach is not entirely
    // accurate for two reasons. First, although the counts from smaller-sized 
    // windows (i.e, windows n-1, n-2, etc.) are logically part of the current
    // window, they have not yet been propagated. (They will be propagated 
    // only when the previous windows are completed.) So, we add those 
    // counts. For efficiency reasons, we just look at the next two windows,
    // which should get us bulk of the count. Second, PREV may not be set.
    // This is sort of similar to the first case, so we handle it almost the
    // same way, with one exception: we add counts from all smaller-size
    // windows, not just the last one. 

     assert(n < 10);
     unsigned i=n;
     unsigned long tc = count(n);
     if (i > 0) tc += count(--i);
     if (i > 0) tc += count(--i);
     if (tc == 0 && isInit(n))
        while (i > 0) 
           tc +=  count(--i);

     unsigned long interval;
     if (i > 0)
        interval = beginTime(i-1) - beginTime(n);
     else interval = beginTime(i) - beginTime(n);
     if (!isInit(n)) {
        interval += winSize(n);
        tc += count(n, PREV);
     }
     if (interval > 0)
        return ((tc*((winSize(n)<<8)/interval))>>8);
     else return tc;
  }

  ostream& printProjCount(ostream& os=cout) const {
     for (unsigned i=0; i < 10; i++) {
        os << projCount(i) << "\t";
     }
     os << endl;
     return os;
  }
*/
};

inline ostream& operator<<(ostream& os, MultiResSlidingCtr c) {
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
*   to worry about counter space, the problem is largely mitigated by using   *
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

