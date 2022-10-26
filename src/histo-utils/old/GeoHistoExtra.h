#ifndef GEOHISTOEXTRA_RAW_INCLUDE
static_assert(false, "Don't include this header file directly");
#endif

/*******************************************************************************
* getProb() takes a single data point and determines the probability that it
* falls within the distribution corresponding to a histogram. This probability
* makes sense ONLY for a SINGLE EVENT. You cannot take the max across a sequence
* of events from the past, e.g., all the n events that have been witnessed in
* the current run of an application. 
*
* If you wanted to work with such maximums, then getProb below should be TOTALLY
* REWRITTEN to return the correct _maximum_ probability among the past n events.
* Alternatively, you may want to compare ALL events produced by a process. For
* that, we can compare two distributions directly, in terms of the corresponding
* histograms. One standard way to compare two distributions is in terms of their
* Kolmogorov-Smirnov distance (wikipedia:Kolmogorov-Smirnov_test).
********************************************************************************/
template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
ProbRes GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
getProb(unsigned long ct) const {
   switch (HistoStats::probAlgo_) {
   case GAP:
      return probGap(ct);
   case DKW:
      return probDKW(ct);
   case CHEBYSHEV:
      return probChebyshev(ct);
   default:
      assert(0);
   }
}

/*******************************************************************************
* See https://en.wikipedia.org/wiki/Dvoretzky-Kiefer-Wolfowitz_inequality
*
* Uses DKW inequality to derive a probability that a new point belongs to a
* distribution represented in this histogram. This is called the empirical
* distribution function F_n which is a CDF (cumulative probability distribution
* function) that exactly matches the n observations. (See
* https://en.wikipedia.org/wiki/Empirical_distribution_function), F_n(x) is
* simply the fraction of observations that were less than x, or more formally:
*
*       F_n(x) = (# of observations <= x)/n
*
* A simple approach is to use F_n directly to estimate P(benign). If we observe
* y during detection --- where y is the number of times an alarm has occured
* within a time window wi --- we can take F_n(y) as P(benign). DKW estimate
* provides more conservative estimate of P(benign). The reason why F_n is too
* aggressive is that the underlying distribution F may be very complex, so the
* samples may not fully or accurately represent it. DKW states that the error
* e (epsilon) is bounded as follows:
*
*     Pr[|F_n(x)-F(x)| > e] <= 2exp(-2n*e^2) = a   for all e > 0
*
* This is called a two-sided estimate since it allows errors on both sides. But
* since we are concerned only about error on one side, i.e., F allows higher
* values than F_n. There is a one-sided error estimate that is half of this:
*
*     Pr[F_n(x)-F(x) > e] <= exp(-2n*e^2) = a for all e >= sqrt(ln(2)/2n)
*
* Here e (epsilon) is the bound on the error resulting from the use of F_n
* instead of the true distribution F, and 1-a (alpha) is the confidence on this
* error bound. 
*
* To use this formula to derive a probability F(x), we compute p = F_n(x) from
* the histograms. Then we pick a global value for 1-a, say, 97.5%. We then use
* the above formula to calculate e, and then set p' = p-e as a conservative
* estimate of F(n). Finally, note that P(benign) is just 1-p'.
*
* We should use the one-sided bound first, but note that we may not be able to
* satisfy the condition on e. In that case, we fall back to using the two-sided
* bound. Note that the 1-sided bound formula, when inverted, yields:
*
*    e = sqrt(ln(1/a)/2n) for one-sided case, provided e >= sqrt(ln(2)/2n)
*    e = sqrt(ln(2/a)/2n) for two-sided case.
*
* It is easy to see that the bounds for 1-sided case will hold whenever a <=
* 0.5. Clearly, we are interested in values of a << 0.5, so we can always use
* the 1-sided estimate.
*
********************************************************************************
* A MAJOR weakness of DKW for our work is that all outliers (points outside of *
* the empirical distribution) are equal to DKW, and return a probability of    *
* zero. A point that is far outside the empirical distribution generates the   *
* same probability as the point that falls barely outside. Chebyshev is much   *
* better in this regard. In practical terms, if you want to set the threshold  *
* at p=1.0, there is nothing in the probability OR error information returned  *
* by DKW that will help you discriminate among different outliers. Chebyshev,  *
* in contrast, returns a probability that is a function of the distance of the *
* outlier.                                                                     *
*******************************************************************************/

inline void HistoStats::
useDKW(float conf, bool useOneSidedErr) {
   HistoStats::probAlgo_ = DKW;
   assert(conf >= 0.75);
   HistoStats::alpha_ = 1-conf;
   HistoStats::dkwfac_ = logf((useOneSidedErr? 1 : 2)/alpha_)/2;
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
ProbRes GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
probDKW(unsigned long ct) const {
   auto [prob, n, gap] = ge(ct, true); 
   float eps = sqrtf(HistoStats::dkwfac_/n);
   return ProbRes(prob, eps);
}

/*******************************************************************************
*             Uses Chebyshev inequality to estimate probability. 
*   See https://en.wikipedia.org/wiki/Chebyshev%27s_inequality. For a broader
*  discussion, also see https://en.wikipedia.org/wiki/Concentration_inequality
*
* Chebyshev inequality says that Pr(|X - mu| >= k*sigma) <= 1/k^2, where mu and
* sigma stand for the population mean and population standard deviation.
* Typically, we have only the sample mean and sample SD, in which case Kaban's
* formula (see the Wikipedia page above) provides the following upper bound:
*
*      Pr(|X-m| >= ks) <= 1/k^2 + 1/n 
*
* This is an approximation of Kaban's formula, which is a bit more complex and
* uses a floor function. Our approximation is an upper bound on that formula.
* Basically, it says that if n is large enough, say, over 100, using sample mean
* and sample SD will yield roughly the same result as using the population mean
* and SD. A better reference on this topic is the original paper "Chebyshev
* Inequality with Estimated Mean and Variance" [Saw et al 1984]. They also have
* a complex formula that can be simplified, with small approximations of the
* order of 1/n, to yield the above bound. The bound is surprising because it is
* so close to the Chebyshev bound, being off by just 10% when n=10. (Or maybe
* 20%, if you count the fact that s has n-1 in the denominator instead of n.)
*
* Chebyshev has a generalization to higher moments --- note that SD is the
* second moment. For the lth moment x, the approximation states:
*
*      Pr(|X-m| >= kx) <= 1/k^l 
*
* It is not clear that there is a version of this that works with sample mean
* and sample moment, but I can't track down a reference. We will continue to
* assume that for n > 100, we can more or less ignore the difference between
* population and sample statistics.
*
* If we are only interested in the case of k > 0, which is the case of interest
* to us, Cantelli's inequality gives a sharp bound (with examples that exactly
* match the inequality):
*
*     Pr(X-\mu >= k\sigma) <= 1/(1+k^2)
*
* This is a slightly better bound, but I can't find versions of this that work
* with sample mean and sample variance. Perhaps this is not a serious problem,
* but the improvement seems rather small, given that we are likely interested in
* relatively large values of k. Besides, this inequality gets rather complex for
* higher moments, so it seems we are better off sticking to Chebyshev's.
*
* For unimodal distributions, Chebyshev's bound can be tightened by a factor of
* 4/9. Guass's inequality is a good place to start on this. But the more
* convenient version is the Vysochanskij-Petunin inequality, which is stated in
* terms of sigma and mu. (In contrast, Gauss's inequality is presented in terms
* of the mode.) It states:
*
*      Pr(|X-\mu| >= k\sigma) <= 4/9k^2, provided k >= sqrt(8/3)
*
* I cannot find a version that works with sample standard deviation, but since
* the correction is rather small for previous techniques, it seems safe to do
* the substitution for n > 50 (almost surely) and perhaps even n > 10 (with
* perhaps no more than 20% error). Version of this inequality exist for higher
* order moments, but it does not seem very useful.
*******************************************************************************/
inline void HistoStats::
useChebyshev(int moment, bool useLogScale, bool tryUnimodal) {
   HistoStats::probAlgo_ = CHEBYSHEV;
   HistoStats::useMoment_ = moment;
   HistoStats::useLogScale_ = useLogScale;
   HistoStats::tryUnimodal_ = tryUnimodal;
   if (tryUnimodal && moment != 2) {
      cerr << "Unimodal flag is disabled with higher order moments\n";
      HistoStats::tryUnimodal_ = false;
   }
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
ProbRes GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
probChebyshev(unsigned long ct) const {
   float constexpr thr = sqrtf(8.0/3);
   float prob;
   unsigned long sum=0, npts=0, minPt=MIN*ONE, fac=0, lastmin=0, v;
   float sum_pow_n=0;
   bool falling=false, unimodal=true; 
   unsigned maxbin=0;

   if (HistoStats::useLogScale_) {
      auto [l, x] = findBin(ct);
      if (x > ONE-x)
         v = l;
      else v=l-1;
   }
   else v = ct;
   
   for (unsigned i=0; i < N; i++) {
      if (bin_[i] > 0) {
         maxbin=i;
         long binval = HistoStats::useLogScale_? i*bin_[i] : minPt+fac*bin_[i];
         npts += bin_[i];
         sum += binval;
         if (HistoStats::useMoment_ == 2)
            sum_pow_n += ((float)binval)*binval;
      }
      if (i == 0) 
         fac = 1;
      else {
         fac <<= LOG2FAC;
         if (falling) {
            if (bin_[i] > ((float)1.2)*lastmin)
               unimodal=false;
            else if (bin_[i] < lastmin)
               lastmin = bin_[i];
         }
         else if (bin_[i] < ((float)0.8)*bin_[i-1]) {
            falling = true;
            lastmin = bin_[i];
         }
      }
   }

   float mean=((float)sum)/npts;
   float moment;
   if (HistoStats::useMoment_ == 2) {
      moment = sqrtf((sum_pow_n - npts*mean*mean)/(npts-1));
      float dev = fabsf(v - mean)/moment;
      if (unimodal && HistoStats::tryUnimodal_ && dev >= thr && npts > 10) 
         prob = 4/(9*dev*dev);
      else prob = 1/(dev*dev);
      prob += 1.0/npts; // Maybe the 1/n term should be added before multiplying
   }  // by 4/9. This is all a guess, so let us go with the conservative option.
   else {
      for (unsigned i=0; i < N; i++) {
         if (bin_[i] > 0) {
            long binv = HistoStats::useLogScale_? i*bin_[i] : minPt+fac*bin_[i];
            sum_pow_n += powf(fabsf(binv-mean), HistoStats::useMoment_);
         }
         if (i == 0) 
            fac = 1;
         else fac <<= LOG2FAC;
      }
      moment = powf((sum_pow_n/(npts-1)), 1.0/HistoStats::useMoment_);
      float dev = fabsf(v - mean)/moment;
      prob = 1/powf(dev, HistoStats::useMoment_);
      if ((npts < 50) && (prob < 0.5))
         cerr << "Use of moment " << HistoStats::useMoment_ 
              << " with n=" << npts << " not recommended\n";
   }
   float maxval = minPt + (1ul<<(maxbin*LOG2FAC));
   float err = (maxval-mean)/(mean*npts);
   return ProbRes(prob, err);
}

/*******************************************************************************
* ProbGap returns a probability value derived from the gap, in terms of number
* of empty bins between the maximum occupied bin in the histogram. The gap is
* defined to be zero if the new count falls in the maximum nonzero bin. Positive
* values mean that the current count is higher than any in the histogram.
*
* How do we turn this into a probability? We can't do this with the kind of
* statistical basis we have in the case of DKW or Chebyshev. Indeed, this is the
* reason to use this method --- there is less of a chance to be swept up in
* false alarms. To give a real statistical basis, perhaps one can run the
* detection against the training data to determine a threshold at which the
* probability values become significant. Then that value could be used as a base
* of some sort. This sort of self-calibration may be useful for DKW and
* Chebyshev as well, but in those cases, we are not trying to calibrate the
* probability scale. Instead, that would be an effort of identifying a
* threshold.
*
* For now, we will return 1/(1+gap^2), similar to Cantelli's formula but
* measured (a) from the maximum instead of mean, and (b) in terms of bins rather
* than standard deviations.
*******************************************************************************/

inline void HistoStats::
useGap() {
   HistoStats::probAlgo_ = GAP;
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
ProbRes GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
probGap(unsigned long ct) const {
#ifdef DEBUG
   cout << "Probgap(" << ct << "): "; print(cout, false, false);
#endif
   auto [prob, err, gap] = ge(ct);

   if (gap == 0)
      return ProbRes(1.0, err);
   // Use gap and npts to compute probability.
   prob = 1.0/(gap*gap+1);// + 10.0/support;
   return ProbRes(prob, err);
}

/********************************************************************************
*          [See https://en.wikipedia.org/wiki/Pareto_distribution]
*
* A final possibility to consider is a power law distribution, given by the PDF
*
*       f(x) = ax^{-k} for k > 2
*
* Note that for k <= 2, such a distribution has infinite mean. For 2 < k <= 3,
* it has infinite variance. Power law distributions are long-tailed (aka
* heavy-tailed) for lower value of k. Zipf and Pareto distributions are two
* prominent examples of power law distributions. For specificity, let us work
* with the Pareto distribution below, which has PDF of the form. 
*
*       f(x) = Pr[X=x] = a(m^a/x^{a+1})
*
* and a CDF:
*
*       F(x) = Pr[X<=x] = 1-(m/x)^a for x >= m
*
* Here, m is the minimum possible value of x and a is called the rank of the
* distribution. The complement of the CDF is called the survival function, and
* it has the simpler form:
*
*       F'(x) = Pr[X>x] = (m/x)^a
*
* There is a lot of literature that shows that a number of phenomena relating to
* application behavior follow the powe law, e.g., there are ssh sessions that
* are very short, but there are others that can be arbitrarily long. Short
* sessions are much more frequent than long ones, with the prevalence decreasing
* continuously as the session length increases. The number of requests processed
* by servers also displays this power law behavior.
*
* When plotted on a log-log scale, both the PDF and CDF become straightlines: if
* you take the log of both sides, you get something of the form:
*
*      log y = k log x
* 
* This makes it easy to visually identify such a distribution. Analytically, a
* better solution is to fit the empirical distribution (a set of points P) to a
* Pareto curve using the following formulas:
*
*      m = min(P)      a = n/[\sum_{x in P} ln(x/m)]
*
* The error in this fit can be computed using Kolmogorov-Smirnov test, which
* computes the maximum difference between the empirical CDF (F_n) and the CDF
* given by a Pareto curve with these parameters (F). This error is easy to
* compute from the statistics. 
*
*        @@@@ We should check the fit before saving the histogram. @@@@
*       [Also see https://en.wikipedia.org/wiki/Kolmogorov-Smirnov_test]
*
* BUT BEFORE PROCEEDING THIS WAY, WE SHOULD EXPERIMENT WITH A FEW DISTRIBUTIONS,
* including log-normal and exponential.
* 
*******************************************************************************/

/*
template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
ProbRes GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
probPowerLaw(unsigned long ct) const {
   double d;
   for (unsigned i=0; i < N; i++) {
      if (bin_[i] > 0) {
         sum += bun_[i]*logf(1+fac); // REQUIRES minPt == 0
         if (HistoStats::useMoment_ == 2)
            sum_pow_n += ((float)binval)*binval;
      }
      if (i == 0) 
         fac = 1;
      else {
         fac <<= LOG2FAC;
         if (falling) {
            if (bin_[i] > ((float)1.2)*lastmin)
               unimodal=false;
            else if (bin_[i] < lastmin)
               lastmin = bin_[i];
         }
         else if (bin_[i] < ((float)0.8)*bin_[i-1]) {
            falling = true;
            lastmin = bin_[i];
         }
      }
   }
}
*/

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
tuple<float, float, uint8_t> 
GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
ge(unsigned long ct, bool returnSupport) const {

   // First, compute the # of entries in this histogram >= ct. Also calculate
   // the total number of points in the histogram. If ct falls in a bin that is
   // to the right of all nonempty bins in the histogram, then also compute the
   // gap between ct's bin and the largest nonempty bin.

   unsigned long sum=0, support=0, minPt=MIN*ONE, fac=1, numGE=0;
   unsigned mybin=0, maxbin=0; uint8_t gap=0;
   unsigned long bin_lo=0, bin_hi=0;
   for (unsigned i=0; i < N; i++) {
      bin_lo = bin_hi;
      bin_hi = minPt + fac;
      if (bin_[i] > 0) {
         maxbin=i;
         long binval = (HistoStats::useLogScale_? i:(bin_lo+bin_hi)/2)*bin_[i];
         sum += binval;
         support += bin_[i];
      }
      if (ct < bin_hi) {
         if (mybin==0)
            mybin=i;
         numGE += bin_[i];
         /*if (i == 0) 
            numGE = bin_[0];
         else numGE = ((float)(bin_[i]*((1 << (i*LOG2FAC)) - ct)))/
                 ((1 << (i*LOG2FAC)) - (1 << ((i-1)*LOG2FAC)));*/
      }
      fac <<= LOG2FAC;
   }

   if (mybin > maxbin)
      gap = mybin - maxbin;

   float prob = ((float)numGE)/support;
   float mean = sum/support;
   float maxval = minPt + (1ul<<(maxbin*LOG2FAC));
   float err = returnSupport? support : (maxval-mean)/(mean*support);
   return make_tuple(prob, err, gap);
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
pair<uint8_t, uint8_t> GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
findBin(unsigned long p) const {
/*
   static const unsigned long a = 6364136223846793005ul; // Knuth's MMIX lin.
   static const unsigned long c = 1442695040888963407ul; // cong. random gen
   static unsigned long r;
*/
#ifdef PRESERVE_MEAN1
   static_assert(MIN==0 && LOG2FAC==1, 
                 "PRESERVE_MEAN1 needs MIN=0, LOG2FAC=1\n");
   if (p < 1) 
      return pair(0, ONE);
   else {
      unsigned l = 64 -__builtin_clzl(p);
      if (l >= N-1) 
         return pair(N-1, ONE);
      else {
         // Attribute p fractionally to bins l and l+1 such that:
         //   (a) we have added exactly one more data point to the histogram
         //   (b) the mean the distribution will be preserved exactly. Let
         // the fractional contributions be x and y. Now:
         //   (a) => x + y = 1
         //   (b) => p = x*2^(l-1) + y*2^l
         // Substituting y = x-1 in the second equation, we get
         //    p = x*2^(l-1) + (1-x)*2^l
         //      = x*(2^(l-1) - 2^l) + 2^l
         // i.e., x = (2^l - p)/(2^l - 2^(l-1))
         //         = (2^l - p)/2^(l-1), OR
         //       y = (p - 2^(l-1))/2^(l-1)
         // What we have below is a randomized version, where random number
         // rr is used to make x and y integral.

         r = a*r + c;
         unsigned long z = (1ul << (l-1));
         unsigned long rr = r >> (65-l);
         unsigned x = (((p-z) << (INCR_BITS-1)) + rr)>>(l-1);
         assert(0 <= x && x <= ONE);
         return pair(l+1, x);
      }
   }

#elif defined(PRESERVE_MEAN)
   // @@@@ Get it to work when LOG2FAC > 1: Preserving mean is a safe option, 
   // @@@@ with less worry about effects of rounding off on probability. 
   static_assert(MIN==0 && LOG2FAC==1 && INCR_BITS==1, 
                 "PRESERVE_MEAN needs MIN=0, LOG2FAC=1, INCR_BITS=1\n");
   if (p < 1) 
      return pair(0, ONE);
   else {
      unsigned l = 64 -__builtin_clzl(p);
      if (l >= N-1) 
         return pair(N-1, ONE);
      else {
         r = (a*r + c);
         if ((r & MAX) < (1ul<<(4*sizeof(BinType)))) compressIfNeeded(); 
         unsigned long z = (1ul << (l-1));
         unsigned long rr = r >> (65-l);
         unsigned x = (p-z > rr);
         return pair(l+1, x);
      }
   }

#else
   assert(p >= MIN);
   p -= MIN; 
   unsigned l;
   if (p < 1) 
      return pair(0, ONE);
   else {
      // Adding LOG2FAC-1 to numerator: round up to next multiple of LOG2FAC
      l = (LOG2FAC-1+8*sizeof(unsigned long) - __builtin_clzl(p))/LOG2FAC;
      assert(l >= 0);
      if (l >= N-1) 
         return pair(N-1, ONE);
      else return pair(l, ONE);
   }
#endif
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
unsigned long GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
npoints() const {
   unsigned long rv=0;
   for (unsigned i=0; i < N; i++)
      rv += bin_[i];
   return rv;
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
merge(const GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>& other) {
   for (unsigned i=0; i < N; i++) {
      BinType res = bin_[i] + other.bin_[i];
      //assert(res >= bin_[i] && res >= other.bin_[i]);
      if (res < bin_[i] || res < other.bin_[i]) {
         assert(i == 0);
         cout << "Histogram Overflow\n"; // To count how often this happens
         res = bin_[i]/2 + other.bin_[i]/2;
      }
      bin_[i] = res;
   }
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
addZero(unsigned long count) {
   count <<= (INCR_BITS-1);
   if (count <= (unsigned long)(MAX - bin_[0]))
      bin_[0] += count;
   else addZero1(count);
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void __attribute__ ((noinline)) GeoHistogram<N,BinType,INCR_BITS,LOG2FAC,MIN>::
addZero1(unsigned long count) {
   for (; count > MAX/2-1; count -= MAX/2-1) {
      compressBins();
      bin_[0] += MAX/2-1;
   }
   if (count > (unsigned long)(MAX - bin_[0]))
      compressBins();
   bin_[0] += count;
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void __attribute__ ((noinline)) GeoHistogram<N,BinType,INCR_BITS,LOG2FAC,MIN>::
compressIfNeeded() {
   for (unsigned i = 0; i < N; i++)
      if (bin_[i] >= MAX) {
         compressBins();
         return;
      }
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
static inline unsigned rotateLeft(unsigned i, unsigned c=1) { 
   return ((i<< c) | (i >> (8*sizeof(unsigned)-c))); 
};

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void __attribute__ ((noinline)) GeoHistogram<N,BinType,INCR_BITS,LOG2FAC,MIN>::
compressBins() {
   static const unsigned a = 1103515245;
   static const unsigned c = 12345;
   static unsigned r;
   // We want to maintain overall distribution without consistently rounding
   // up or down. We use a random number generator for this purpose. Assuming
   // that all bits are random, we pick the ith bit for the ith bin.
   r = a*r+c;
   unsigned r1 = r;
   for (unsigned i = 0; i < N; i++) {
      if (bin_[i] > 0) {
         r1 = 0;//rotateLeft(r1);
         bin_[i] = (bin_[i] + (r1&0x1)) >> 1;
      }
   }
}

template <unsigned N,typename BinType,unsigned INCR_BITS,int LOG2FAC,int MIN>
void GeoHistogram<N, BinType, INCR_BITS, LOG2FAC, MIN>::
print(std::ostream& os, bool cumulative, bool normalize) const {
   double sum=0; unsigned maxnzbin=0;
   float minPt = MIN; 

   float npts=0;
   for (unsigned i=0; i < N; i++) {
      if (bin_[i] > 0) {
         maxnzbin=i;
         npts += bin_[i];
      }
   }

   float c = 0; 
   unsigned long f=1;

   for (unsigned i=0; i <= maxnzbin; i++) {
      sum += (minPt*ONE) + ((double)((f + (f>>LOG2FAC))/2)) * bin_[i];
      f <<= LOG2FAC;
   }

   os << "Range: " << MIN << " to " 
      << MIN+((1ul << ((N-1)*LOG2FAC))-1) << " max non-zero bin: "
      << MIN+((1ul << (maxnzbin*LOG2FAC))-1) 
      << "   N: " << npts/ONE << " Mean: " << sum/npts << std::endl;

   for (unsigned i=0; i <= maxnzbin; i++) {
      c = cumulative ? c + bin_[i] : bin_[i];
      float p = normalize? c/npts : c/ONE;
      os << p << ' ';
   }
   os << std::endl; 
}

