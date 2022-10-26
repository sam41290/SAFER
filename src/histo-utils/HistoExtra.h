#define SelfParams <class Bin, class ElemType, class BinType>
#define Self Histogram<Bin, ElemType, BinType>

#ifdef DEBUG
#define debugprt(s, ct) \
   cout << "prob" << s << '(' << ct << "): "; \
   print(cout, false, false);
#else
#define debugprt(x,y)
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
template SelfParams
ProbRes Self::
getProb(ElemType v) const {
   switch (HistoStats::probAlgo_) {
   case ProbAlgo::GAP:
      debugprt("Gap", v);
      return probGap(v);
   case ProbAlgo::DKW:
      debugprt("DKW", v);
      return probDKW(v);
   case ProbAlgo::CHEBYSHEV:
      debugprt("Cheb", v);
      return probChebyshev(v);
   default:
      assert_abort(0);
   }
}

#undef debugprt
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
* at p=1.0, there is nothing in the probability OR the *error* term returned   *
* by DKW that will help you discriminate among different outliers. Chebyshev,  *
* in contrast, returns a probability that is a function of the distance of the *
* outlier.                                                                     *
*******************************************************************************/

inline void HistoStats::
useDKW(double conf, bool useOneSidedErr) {
   HistoStats::probAlgo_ = DKW;
   assert_try(conf >= 0.75);
   HistoStats::alpha_ = 1-conf;
   HistoStats::dkwfac_ = log((useOneSidedErr? 1 : 2)/alpha_)/2;
}

template SelfParams
ProbRes Self::
probDKW(ElemType v) const {
   auto [prob, n, gap] = ge(v, true); 
   double eps = (n==0? 1.0 : sqrt(HistoStats::dkwfac_/n));
   return ProbRes(min(prob+eps, 1.0), eps);
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
* assume that for large enough n, we can more or less ignore the difference
* between population and sample statistics. For this implementation, we treat 25
* as large enough. (Revisit if needed, but do it for all occurences of 25.)
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
* the substitution for n > 50 (almost surely) and perhaps even n > 25 (with
* perhaps no more than 20% error). Version of this inequality exist for higher
* order moments, but it does not seem very useful.
*******************************************************************************/
inline void HistoStats::
useChebyshev(unsigned moment, bool useBinNumber, bool tryUnimodal) {
   HistoStats::probAlgo_ = CHEBYSHEV;
   HistoStats::useMoment_ = moment;
   HistoStats::useBinNumber_ = useBinNumber;
   HistoStats::tryUnimodal_ = tryUnimodal;
   if (tryUnimodal && moment != 2) {
      cerr << "Unimodal flag is disabled with higher order moments\n";
      HistoStats::tryUnimodal_ = false;
   }
}

template SelfParams
ProbRes Self::
probChebyshev(ElemType pt) const {
   bool falling=false, unimodal=true; 
   uint64_t npts=0;
   unsigned maxnzbin=0;
   double prev_binct, binct=0, binval, bin_lo=0, bin_hi=Bin::start(0);
   double sum=0, sum_pow_n=0, lastmin=0;
   int usemoment = HistoStats::useMoment_;

   for (unsigned i=0; i < Bin::nbins(); i++) {
      bin_lo = bin_hi;
      if (i < Bin::nbins()-1) 
         bin_hi = Bin::start(i+1);
      prev_binct = binct;
      binct = bin_[i];

      if (binct > 0) {
         maxnzbin=i;
         npts += binct;
         if (HistoStats::useBinNumber_)
            binval = i;
         else binval = (bin_lo+bin_hi)/2;
         double x = binct*binval;
         sum += x;
         sum_pow_n += x*binval;
      }

      if (!falling) {
         if (binct < 0.8*prev_binct) {
            falling = true;
            lastmin = binct;
         }
      }
      else if (binct > 1.2*lastmin)
         unimodal=false;
      else if (binct < lastmin)
         lastmin = binct;
   }

   if (npts <= 1)
      return ProbRes(1.0, 1.0);

   if (HistoStats::tryUnimodal_) {
      if (!unimodal)
         cerr << "Disabling unimodal: distribution has multiple peaks?\n";
   }
   else unimodal = false;
   if (npts < 25 && (HistoStats::tryUnimodal_ || usemoment != 2)) {
#ifdef DEBUG
      cerr << "Disabling unimodal and/or higher order moments for n="
           << npts << " points\n";
#endif
      unimodal=false;
      usemoment=2;
   }
   double mean=sum/npts, v;
   if (HistoStats::useBinNumber_)
      v = Bin::bin(pt);
   else v = pt;

   const double thr = sqrt(8.0/3);
   double prob, moment, dev;
   if (v < mean) {
      prob=moment=dev=1.0;
   }
   else if (usemoment == 2) {
      moment = sqrt((sum_pow_n - npts*mean*mean)/(npts-1));
      if (moment < 1e-10) moment = 1e-10;
      dev = fabs(v - mean)/moment;
      if (dev < 1e-20) dev = 1e-20;
      if (unimodal &&  dev >= thr) {
#ifdef DEBUG
         if (dev < 1e10) cout << "*********** Using unimodal\n";
#endif
         prob = 4/(9*dev*dev);
      }
      else prob = 1/(dev*dev);
      prob += 1.0/npts; // Maybe the 1/n term should be added before multiplying
   }  // by 4/9. This is all a guess, so let us go with the conservative option.
   else {
      bin_hi=Bin::start(0); sum_pow_n=0;
      for (unsigned i=0; i <= maxnzbin; i++) {
         bin_lo = bin_hi;
         if (i < Bin::nbins()-1) 
            bin_hi = Bin::start(i+1);
         binct = bin_[i];
         if (binct > 0) {
            if (HistoStats::useBinNumber_)
               binval = i;
            else binval = (bin_lo+bin_hi)/2;
            sum_pow_n += binct*pow(fabs(binval-mean), usemoment);
         }
      }
      moment = pow(sum_pow_n/(npts-1), 1.0/usemoment);
      if (moment < 1e-10) moment = 1e-10;
      dev = fabs(v - mean)/moment;
      if (dev < 1e-20) dev = 1e-20;
      prob = 1/pow(dev, usemoment);
   }

   // We calculate the error in the same way as probgap, as coded in ge()
   double maxval = HistoStats::useBinNumber_? maxnzbin : Bin::start(maxnzbin+1);
   double err = (maxval-mean)/(1e-10 + mean*npts);
   if (prob > 1.0) prob = 1.0;
   if (err > 1.0) err = 1.0;
#ifdef DEBUG
   cout <<"v="<<v<<" mean="<<mean<<" max="<<maxval
        <<" moment="<< moment<<" dev="<<dev<<endl;
#endif
   return ProbRes(prob, err);
}

/*******************************************************************************
* ProbGap was *intended* to return a probability that is derived from the gap,
* in terms of number of empty bins between a given point and the maximum
* occupied bin in the histogram. The gap is defined to be zero if the new count
* falls in the maximum nonzero bin. Positive values mean that the current count
* is higher than any in the histogram.
*
* Since histogram bins may be non-uniform in size, the current calculation
* relies on something that is less dependent on the binning: instead, we use the
* logarithm of the ratios of the upper bounds of the bins. In the case of a
* geometric histogram where the ranges increase by a factor of e from one bin to
* the next, this new measure will exactly match the definition of gap. More
* importantly, this quantity will remain invariant if a uniformly sized
* histogram (i.e., every bin captures the exact same range), or if the ratio
* used in a geometric histogram is changed.
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
* For now, we will return 1/(1+gap^2) as the probability, similar to Cantelli's
* formula but measured (a) from the maximum instead of mean, and (b) as a
* logarithm of the ratio with this maximum element, rather than using the
* standard deviation.
*
* For the error, we wave our hands even more vigorously. The question we use for
* this purpose is: suppose that the distribution we have is off by one point.
* Conservatively, assume that this point falls at the maximum end of the
* distribution. The relative error to the mean that would be introduced by such
* a point is taken as an estimate of the error.
*******************************************************************************/

inline void HistoStats::
useGap() {
   HistoStats::probAlgo_ = ProbAlgo::GAP;
}

template SelfParams
ProbRes Self::
probGap(ElemType ct) const {
   auto [prob, err, gap] = ge(ct);

   // Use gap and npts to compute probability.
   prob = 1.0/(gap*gap+1);
   if (err > 1.0) err = 1.0;
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
template SelfParams
ProbRes Self::
probPowerLaw(unsigned long ct) const {
   double d;
   for (unsigned i=0; i < Bin::nbins(); i++) {
      if (bin_[i] > 0) {
         sum += bun_[i]*logf(1+fac); // REQUIRES minPt == 0
         if (HistoStats::useMoment_ == 2)
            sum_pow_n += ((double)binval)*binval;
      }
      if (i == 0) 
         fac = 1;
      else {
         fac <<= LOG2FAC;
         if (falling) {
            if (bin_[i] > ((double)1.2)*lastmin)
               unimodal=false;
            else if (bin_[i] < lastmin)
               lastmin = bin_[i];
         }
         else if (bin_[i] < ((double)0.8)*bin_[i-1]) {
            falling = true;
            lastmin = bin_[i];
         }
      }
   }
}
*/

template SelfParams
tuple<double, double, double> 
Self::
ge(ElemType pt, bool returnSupport) const {

   // First, compute the # of entries in this histogram >= pt. Also calculate
   // the total number of points in the histogram. If pt falls in a bin that is
   // to the right of all nonempty bins in the histogram, then also compute the
   // gap between pt's bin and the largest nonempty bin.

   ElemType bin_lo=0, bin_hi=Bin::start(0);
   unsigned long support=0, numGE=0;
   unsigned mybin=0, maxnzbin=0;
   double sum=0, gap=0;

   for (unsigned i=0; i < Bin::nbins(); i++) {
      bin_lo = bin_hi;
      if (i < Bin::nbins()-1) 
         bin_hi = Bin::start(i+1);
      if ((uint64_t)bin_[i] > 0) {
         maxnzbin=i;
         double binval = bin_lo;
         binval = (binval+bin_hi)/2;
         sum += binval * (double)bin_[i];
         support += (uint64_t)bin_[i];
      }
      if (pt < bin_hi) {
         if (mybin==0)
            mybin=i;
         numGE += (uint64_t)bin_[i];
      }
   }

   if (support == 0)
      return make_tuple(1.0, (returnSupport? 0:1), 0);
   double prob = ((double)numGE)/support;
   double mean = sum/support;
   double maxval = Bin::start(maxnzbin+1);
   if (mybin > maxnzbin)
      gap = log(Bin::start(mybin+1)/maxval);

   // Error calculates the relative error in the mean if the histogram
   // included one more instance of the largest element in it.
   double err = returnSupport? support :
                (maxval-mean)/(1e-10+mean*support);
   return make_tuple(prob, err, gap);
}

template SelfParams
unsigned long Self::
npoints() const {
   unsigned long rv=0;
   for (unsigned i=0; i < Bin::nbins(); i++)
      rv += (uint64_t)bin_[i];
   return rv;
}

template SelfParams
void Self::
merge(const Self& other) {
   for (unsigned i=0; i < Bin::nbins(); i++) {
      //uint64_t a=(uint64_t)bin_[i], b=(uint64_t)other.bin_[i], c=a+b;
      bin_[i] += (uint64_t)other.bin_[i];
      //a=(uint64_t)bin_[i];
      //assert_abort(a==c);
      //assert(bin_[i].isExact()!=0);
   }
}

template SelfParams
void Self::
print(std::ostream& os, bool cumulative, bool normalize) const {
   double sum=0; unsigned maxnzbin=0;

   double npts=0;
   for (unsigned i=0; i < Bin::nbins(); i++) {
      if (bin_[i] != 0) {
         maxnzbin=i;
         npts += (double)bin_[i];
      }
   }

   for (unsigned i=0; i <= maxnzbin; i++) {
      double binval = Bin::start(i);
      if (i < Bin::nbins()-1)
         binval = (binval+Bin::start(i+1))/2;
      sum += binval * (double)bin_[i];
   }

   os << "Range: " << Bin::start(0) << " to " << Bin::start(maxnzbin+1);
   /*if (maxnzbin < Bin::nbins()-1)
      os << Bin::start(maxnzbin+1)-1;
   else os << "over " << Bin::start(maxnzbin);*/
   os << "   N: " << npts << " Mean: " << (1e-50+sum)/(1e-50+npts) << std::endl;

   double c = 0; 
   for (unsigned i=0; i <= maxnzbin; i++) {
      c = cumulative ? c + (double)bin_[i] : (double)bin_[i];
      double p = normalize? c/npts : c;
      os << p << ' ';
   }
   os << std::endl; 
}

#undef SelfParams
#undef Self
