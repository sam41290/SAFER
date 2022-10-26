#ifndef MULTI_RES_CTR_H
#define MULTI_RES_CTR_H
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>

using namespace std;

// Default template arguments sized for base window size of 16 ticks, with
// window sizes increasing by a factor of 16. If a tick is 1 ns then the largest
// time window is 16*(2**((NUM_SCALES-1)*4)) = 2^56 ns = 2.285 years. Another
// possible combination is a base of 256ns with windows increasing by a factor
// of 8, which yields a maximum window size of 1.6 days.

template<class CtrRep, unsigned NUM_SCALES=14, unsigned LOG2_WIN_SCALE=4,
         unsigned LOG2_WIN_BASE=4>
class MultiResCtr {
 protected:
  CtrRep count_[NUM_SCALES];
  unsigned char log2WinBase_;
  unsigned long beginTime_: 56;

 public:
  MultiResCtr(unsigned long startTime, unsigned log2BaseWinSize=LOG2_WIN_BASE): 
     log2WinBase_(log2BaseWinSize), beginTime_(startTime) {};

  MultiResCtr(unsigned log2BaseWinSize=LOG2_WIN_BASE): 
     log2WinBase_(log2BaseWinSize), beginTime_(0) {};

  // Returns the window size for the counter at nth resolution
  unsigned long winSize(unsigned n) const {
     assert_abort(n < NUM_SCALES);
     return 1ul << (log2WinBase_ + n*LOG2_WIN_SCALE);
  }

  // Returns the begin time for the counter at nth resolution. If beginTime_=1023
  // and winsize=[16,64,256,...], then beginTime=[1008,768,0,...]
  unsigned long beginTime(unsigned n) const {
     return beginTime_ & (~(winSize(n)-1));
  }

  // Note that
  // current count at nth resolution counter includes counts since beginTime(n).
  // However, due to how it is implemented, these counts may not yet
  // have been propagated from count_[CURR][n-1] to count_[CURR][n]. To get
  // the correct value of current count at resolution n, you need to compute:
  //     sum_{i=0}^n count_[CURR][i]

  // Time starts at zero, when the object is created or reset. All increment
  // operations must provide a time that is relative to object creation time.
  // Obviously, time does not need to be related to chronological or wall clock
  // time. It can be logical time, e.g., a counter; the only requirement is
  // that it should not go backwards.

  void inc(unsigned long t, unsigned ct=1, bool callAdv=true) {
     if (callAdv && (t - beginTime_ >= (1u << log2WinBase_)))
        advance(t);
     count1_[CURR][0] += ct;
  }

  // Projected count is primarily based on PREV count. However, for larger n,
  // PREV count is out of date. Indeed, it may not even have been set once.
  // So, we use a combination of CURR and PREV values to project a count 
  // corresponding to the last winSize(n) seconds.

  unsigned long projCount(unsigned n) const {
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

  // Low-level function that returns the raw current value of nth counter. 
  // It is more likely that you are interested in projCount()

  unsigned long count(unsigned n, unsigned c=CURR) const {
     if (n < 2)
        return count1_[c][n];
     else if (n<6)
        return count2_[c][n-2];
     else if (n < 10)
        return count3_[c][n-6];
     else assert(false);
  }

  void count(unsigned n, unsigned c, unsigned long v) {
     if (n < 2)
        count1_[c][n] = v;
     else if (n<6)
        count2_[c][n-2] = v;
     else if (n < 10)
        count3_[c][n-6] = v;
     else assert(false);
  }

  bool isInit(unsigned n) const {
     if (n < 2)
        return (count1_[PREV][n] == 0xffff);
     else if (n<6)
        return (count2_[PREV][n-2] == ~0u);
     else if (n < 10)
        return (count3_[PREV][n-6] == ~0ul);
     else assert(false);
  }

  ostream& print(ostream& os=cout) const {
     for (unsigned i=0; i < 10; i++) {
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

  void advance(unsigned long t) {
     unsigned i; unsigned long wsize, begTime;
     for (i=0; i < 10; i++) {
        wsize = winSize(i); begTime = beginTime(i);
        if (t - begTime >= wsize) {
           if (i+1 < 10) // add counts accumulated at the ith resolution counter
              count(i+1, CURR, count(i+1) + count(i)); // to resolution i+1
           if (t - begTime < 2*wsize)
              count(i, PREV, count(i));
                 // Shift count from currrent to previous window
           else count(i, PREV, 0);
           count(i, CURR, 0);
       }
       else break; // If the window for ith resolution didnt advance, ctr at i+1
    }              // resolution certainly wont advance, so skip more loop iters
    beginTime_ = t;
    beginTime_ = beginTime(0);
  }
};

inline ostream& operator<<(ostream& os, MultiResCtr c) {
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

