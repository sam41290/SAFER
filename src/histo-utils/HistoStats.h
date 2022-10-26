#ifndef HISTO_STATS_H
#define HISTO_STATS_H

/*******************************************************************************
* The primary purpose of histograms is to maintain a distribution. If you have a
* distribution, the most obvious question you can ask concerns the probability
* that a given point belongs to the distribution. A set ot data types and
* functions related to these statistics are defined below. Ideally, these
* functions will be defined within the Histogram class, but since it happens to
* be a template class, definitions inside the class would be considered distinct
* for every instance. This is not what we want, so we bite the bullet and create
* a separate header file for this.
*******************************************************************************/

struct ProbRes { // Struct returns estimated probability and error in estimate.
   float  prob;  // Some methods, e.g., DKW, provide error estimate directly.
   float  err;   // For others (Chebyshev and gap), we return the quantity
                 // (maxvalue-mean)/(mean*numpoints). This error estimate lacks
   ProbRes(double p=1, double e=1) {   // a theoretical, basis but a simple 
     prob=p;     // explanation is that it represents the relative error in mean
     err=e;      // if we missed one additional point that has the same value 
   }             // as the maximum in the distribution. For skewed (but maybe 
                 // not long-tailed) distribs, this seems like a fine estimate.
   ProbRes(const ProbRes& pr) {operator=(pr);}
   const ProbRes& operator=(const ProbRes& pr) { 
      prob = pr.prob; err = pr.err; return *this;
   }
   bool operator==(const ProbRes& pr) const {
      return (prob==pr.prob && err==pr.err);
   }
   bool operator!=(const ProbRes& pr) const { return !(operator==(pr));}
   bool operator<(const ProbRes& pr) const {
      if (prob - 0.1 < pr.prob) // Close enough, check error
         return (prob-pr.prob < 0.1*(pr.err-err));
      else return false;
   }
   bool operator>(const ProbRes& pr) const { return pr.operator<(*this);};
   bool operator>=(const ProbRes& pr) const { return !(operator<(pr)); };
   bool operator<=(const ProbRes& pr) const { 
      return (operator<(pr) || operator==(pr)); 
   };
};

enum ProbAlgo {GAP, DKW, CHEBYSHEV};

struct HistoStats {
   inline static ProbAlgo probAlgo_;
   inline static double alpha_, dkwfac_;
   inline static int useMoment_;
   inline static bool useBinNumber_;
   inline static bool useOneSidedErr_;
   inline static bool tryUnimodal_;

   // Use DKW inequality to estimate the error. The error estimate is based on
   // the confidence level parameter. The flag indicates whether the one-sided
   // or symmetric version of the inequality should be used.
   static void useDKW(double confidence, bool useOneSidedErr);

   // Use Chebyshev inequality to estimate probability. The first parameter 
   // indicates the moment to use --- for the default, use moment = 2. Higher
   // moments may be better at capturing long-tailed distributions. The second
   // flag says to operate on log(count) instead of count. The last flag says
   // we should use the tighter bound applicable to unimodal distributions *if*
   // the empirical distribution is indeed unimodal.
   static void useChebyshev(unsigned moment, bool useBinNum, bool tryUnimodal);

   // Use an ad-hoc technique based on the gap, i.e., the number of empty bins
   // between the max nonzero bin in the histogram and the bin of the next 
   // point. The actual algorithm uses the log of the ratio of maximums of
   // the bins in prder that it can work with all types of histograms.
   static void useGap();
};
#endif
