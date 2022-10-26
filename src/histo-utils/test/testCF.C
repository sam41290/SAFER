#include <iostream>
#include "CompactFloat.h"
#include <math.h>

// Random number generator that is biased to generate more smaller numbers.
// Prob(k bits) should be proportional to (64-k)^2, but are not getting there.
// But the distribution is good enough, with smaller number of bits appearing
// 16x to 32x times more often as 60+ bits.

uint64_t nextr(bool prtStats=0) { // 
   static const unsigned long a = 6364136223846793005ul; // Knuth's MMIX lin.
   static const unsigned long c = 1442695040888963407ul; // cong. random gen
   static unsigned long rr, nb, nbhisto[64], totnb=0,m=0;

   unsigned discardbits = max(rr & 0x3f, (rr>>32) & 0x3f);
   rr = a*rr + c;
   uint64_t r = rr >> discardbits;
   nb = (r==0? 0 : 64-__builtin_clzl(r));
   totnb += nb;
   nbhisto[nb]++; m++;

   if (prtStats) {
      cout << "Avg # of bits in random numbers: " << (totnb/(double)m) 
           << " Histogram of # of bits (log2 scale) printed below\n";
      for (int i=0; i < 64; i++)
         cout << (int)(log2(nbhisto[i])) << ' ';
      cout << endl;
   }
   return r;
}

long nconv, nop;

// Tests conversions into CompactFloat and back. Select a random integer r
// within the range of CompactFloat (but obviously, an integer can't exceed
// 2^{64}-1). Convert r into CompactFloat and back, calculate relative error.
// The error should be within 1/2^p where p is the precision (bits in the
// mantissa). Error messages are printed for each trial where the deviation
// exceeds this limit. At the end, a summary is printed that captures the
// maximum deviation and compares it with 1/2^p limit. (Note that very small
// numbers are represented with fewer than p bits, so the errors may be 
// higher there. We take that into account here.)

template <class RepType, unsigned MBITS, unsigned EBITS, bool NEG=true, 
         bool ENEG=true, bool EPOS=true>
void testFloat(long n) {
   CompactFloat<RepType, MBITS, EBITS, NEG, ENEG, EPOS> y;
   double dev=0, maxdev=0;
   unsigned m = 0;
   double exp_dev = 1./(1<<MBITS);
   uint64_t maxr = EPOS? (long)min(((double)(~0ul)), y.maxf()) : ~0ul;
   for (unsigned i=0; i < n; i++) {
      uint64_t r = nextr();
      if (maxr < (1ul<<61))
         r = r % maxr;
      if (r > 0 && r < maxr) {
         double r1 = r;
         if (ENEG && (!EPOS || (r & 1)))
            r1 = 1/r1;
         if (NEG && (r & 2))
            r1 = -r1;
         y = r1;
         double dy = y.dval();
         double r2 = fabs(1.0 - dy/r1);
         if (r2 > exp_dev) {
            // Smallest numbers are represented with leading zeroes in mantissa,
            // which reduces precision. Take this into account.
            double yy = fabs(y.minpos()/r1);
            if (r2 > 2*yy)
               cout<< "r=" << r1<< ", y=" << dy << ", dev=" << r2 << '\n';
         }
         dev += r2;
         if (r2 > maxdev)
            maxdev=r2;
         m++;
      }
   }
   cout << "Cvt: Avg dev on " << m << " samples: " << dev/m 
        << "\tmax=" << maxdev << "\texpected=" << exp_dev << "\n";
   nconv += m;
}

enum Op {PLUS, MINUS, MULT, DIV};
string opName[] = {"+", "-", "*", "/"};

template <class RepType, unsigned MBITS, unsigned EBITS, bool NEG, 
         bool ENEG, bool EPOS>
void testOp(long n, Op op, unsigned long rpt=0) {
   CompactFloat<RepType, MBITS, EBITS, NEG, ENEG, EPOS> y, z, w;
   double dev=0, maxdev=0;
   unsigned m = 0;
   double exp_dev = 2.0/(1<<MBITS);
   uint64_t maxr = EPOS? (long)min(((double)(~0ul)), y.maxf()) : ~0ul;
   for (unsigned i=0; i < n; i++) {
      uint64_t r = nextr();
      if (maxr < (1ul<<61))
         r = r % maxr;
      if (r > 0 && r < maxr) {
         double r1 = r;
         if (ENEG && (!EPOS || (r & 1)))
            r1 = 1/r1;
         if (NEG && (r & 2))
            r1 = -r1;
         z = y;
         z.mantissa(w.mantissa() ^ y.mantissa());
         y = (double)r1;
         double d1 = y.dval();
         double d2 = z.dval();
         r1 = (op == PLUS)? d1 + d2 : (op == MINUS? d1-d2 : d1*d2);
         double dd = max(fabs(d1), fabs(d2));
         if (dd <= fabs(r1))
            dd = 1.0;
         else dd = fabs(r1)/dd;
         if (r1 < y.maxf() && y.minf() <= r1) {
            w = (op == PLUS)? y + z : (op == MINUS? y - z : y * z);
            m++;
            double r2 = fabs(1.0 - (w.dval()+1e-304)/(r1+1e-304))*dd;
            if (r2 > exp_dev || isnan(r2)) {
               cout << d1 <<' ' << opName[op] << ' '<<d2<<" = "<< w.dval()
                    << " (expected " << r1 << ", dev="<<r2<<")\n";
               w = (op == PLUS)? y + z : (op == MINUS? y - z : y*z);
            }
            dev += r2;
            if (r2 > maxdev)
               maxdev=r2;
            for (unsigned j=0; j < rpt; j++) {
               z.mantissa(w.mantissa() ^ y.mantissa());
               w = (op == PLUS)? y + z : (op == MINUS? y - z : y * z);
            }
         }
      }
   }
   cout << "Op " << opName[op] << ": Avg dev on " << m << " samples: " << dev/m 
        << "\tmax=" << maxdev << "\texpected=" << exp_dev << "\n";
   nop += m*(rpt+1);
}

template <class RepType, unsigned MBITS, unsigned EBITS, bool NEG, 
         bool ENEG, bool EPOS>
void testMult(long n, unsigned long rpt=0) {
   CompactFloat<RepType, MBITS, EBITS, NEG, ENEG, EPOS> y, z, w;
   double dev=0, maxdev=0;
   unsigned m = 0;
   double exp_dev = 2./(1<<MBITS);
   uint64_t maxr = EPOS? (long)min(((double)(~0ul)), y.maxf()) : ~0ul;
   for (unsigned i=0; i < n; i++) {
      uint64_t r = nextr();
      if (maxr < (1ul<<61))
         r = r % maxr;
      if (r > 0 && r < maxr) {
         double r1 = r;
         if (ENEG && (!EPOS || (r & 1)))
            r1 = 1/r1;
         if (NEG && (r & 2))
            r1 = -r1;
         z = y;
         z.mantissa(w.mantissa() ^ y.mantissa());
         y = (double)r1;
         double d1 = y.dval();
         double d2 = z.dval();
         r1 = d1*d2;
         double dd = max(fabs(d1), fabs(d2));
         if (dd <= fabs(r1))
            dd = 1.0;
         else dd = fabs(r1)/dd;
         if (r1 < y.maxf() && y.minf() <= r1) {
            w = y * z;
            m++;
            double r2 = fabs(1.0 - (w.dval()+1e-304)/(r1+1e-304))*dd;
            if (r2 > exp_dev || isnan(r2)) {
               cout << d1 << " * " << d2 <<" = " << w.dval()
                    << " (expected " << r1 << ", dev="<<r2<<")\n";
               w = y*z;
            }
            dev += r2;
            if (r2 > maxdev)
               maxdev=r2;
            for (unsigned j=0; j < rpt; j++) {
               z.mantissa(w.mantissa() ^ y.mantissa());
               w = y * z;
            }
         }
      }
   }
   cout << "Op *: Avg dev on " << m << " samples: " << dev/m 
        << "\tmax=" << maxdev << "\texpected=" << exp_dev << "\n";
   nop += m*(rpt+1);
}

bool static prtsum;

template <class RepType, unsigned MBITS, unsigned EBITS, bool NEG=true, 
         bool ENEG=true, bool EPOS=true>
void testRepOp(long n, uint64_t a, uint64_t b, Op op) {
   CompactFloat<RepType, MBITS, EBITS, NEG, ENEG, EPOS> x=a, y=b;

   for (long i=0; i< n; i++)
      x = (op==PLUS)? x + y : x - y;

   double exp = a;
   if (op == PLUS)
      exp += n*b;
   else exp -= n*b;

   if (prtsum)
      cout << "Op " << opName[op] << ": Avg dev after " << n << " operations: " 
           << fabs(1 - (x.dval()+1e-304)/(exp+1e-304)) 
           << "\texpected=" << exp << "\tactual=" << x.dval() << "\n";
   nop += n;
}

// Tests conversions into CompactLong and back. Select a random integer r
// within the range of CompactFloat (but obviously, an integer can't exceed
// 2^{64}-1). Convert r into CompactFloat and back, calculate relative error.
// The error should be within 1/2^p where p is the precision (bits in the
// mantissa). Error messages are printed for each trial where the deviation
// exceeds this limit. At the end, a summary is printed that captures the
// maximum deviation and compares it with 1/2^p limit.

template <class RepType, unsigned MBITS, unsigned EBITS, bool NEG>
void testLong(long n) {
   CompactFloat<RepType, MBITS, EBITS, NEG, false, true> y;
   double dev=0, maxdev=0;
   uint64_t m = 0;
   double exp_dev = 1.0/(1<<MBITS);
   for (unsigned i=0; i < n; i++) {
      uint64_t r = nextr();
      double r2, d;
      if (NEG) {
         if (((long)r) < 0 || (i & 1) == 0) {
            y = (long)r;
            d = (long)r;
         }
         else {
            y = -(long)r;
            d = -(long)r;
         }
      }
      else {
         y = r;
         d = r;
      };
      m++;
      if (NEG)
         r2 = (y.lval()+1e-304)/(1e-304+d);
      else r2 = (1e-304+y.ulval())/(1e-304+d);
      r2 = fabs(1.0 - r2);
      if (r2 > exp_dev) {
         cout<< "r=";
         if (NEG)
            cout << (long)r;
         else cout << r;
         cout << ", y=" << y.dval() << " (";
         if (NEG)
            cout << y.lval();
         else cout << y.ulval();
         cout << "), dev=" << r2 << '\n';
      }
      dev += r2;
      if (r2 > maxdev)
         maxdev=r2;
   }

   cout << "Cvt: Avg dev on " << m << " samples: " << dev/m 
        << "\tmax=" << maxdev << "\texpected=" << exp_dev << "\n";
   nconv += m;
}

#ifdef TRACK
double diff, sumr;
long nadj;
#endif

int logLevel=0;
int main(int argc, char* argv[]) {
   long n = 10000, m = 10000;
   if (argc > 1) n = atol(argv[1]);
   if (argc > 2) m = atol(argv[2]);

   testFloat<uint16_t, 3, 6, 0, 0, 1>(n);
   testFloat<uint16_t, 11, 6, 0, 0, 1>(n);
   testFloat<uint16_t, 6, 10, 1, 1, 1>(n);
   testFloat<uint16_t, 8, 9, 0, 1, 0>(n);
   testFloat<uint32_t, 26, 7, 0, 1, 0>(n);
   testFloat<uint32_t, 26, 6, 1, 1, 1>(n);//Errors are about 10x what is
   // expected when converting numbers in the range of 1e-10. Investigate.

   // Looks like abt 7-8ns/op with O2 and O3
   testOp<uint16_t, 3, 6, 0, 0, 1>(n, PLUS);
   testOp<uint16_t, 11, 6, 0, 0, 1>(n, PLUS);
   testOp<uint16_t, 6, 10, 1, 1, 1>(n, PLUS);
   testOp<uint16_t, 8, 9, 0, 1, 0>(n, PLUS);
   testOp<uint32_t, 26, 7, 0, 1, 0>(n, PLUS);

   // About 9-10ns/op
   testOp<uint16_t, 3, 6, 0, 0, 1>(n, MINUS);
   testOp<uint16_t, 11, 6, 0, 0, 1>(n, MINUS);
   testOp<uint16_t, 6, 10, 1, 1, 1>(n, MINUS);
   testOp<uint16_t, 8, 9, 0, 1, 0>(n, MINUS);
   testOp<uint32_t, 26, 7, 0, 1, 0>(n, MINUS);

   testLong<uint8_t, 3, 6, 0>(n);
   testLong<uint16_t, 6, 7, 1>(n);
   testLong<uint32_t, 26, 6, 1>(n);

   for (int i=0; i < m; i++) { // 5-6ns/operation in this loop
      if (i==m-1) prtsum=1;
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 1, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 2, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 4, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 6, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 8, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 12, PLUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(10000, 30000, 16, PLUS);
      
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 1, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 2, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 4, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 6, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 8, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 12, MINUS);
      testRepOp<uint16_t, 8, 6, 0, 0, 1>(1000, 40000, 16, MINUS);

      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 1, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 2, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 4, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 6, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 11, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 12, PLUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(1000000, 300000, 16, PLUS);
      // Average error of 1.5% across the above, 2% on the the first. 
      // Note that number 1 is 7+ digits to the right of the least
      // significant digit of 300K. In fact, towards the end of 
      // the loop adding 1's, it is 11 digits to the right the least
      // significant digit. Still, we get 2% error, which is the
      // equivalent of working with 6 rather than 11 bits of mantissa.
      // So, we are doing at least 5 bits more of precision because
      // of randomized correction. More important, the error remains
      // very stable as we increase the number of iterations.

      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 1, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 2, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 4, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 6, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 11, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 12, MINUS);
      testRepOp<uint16_t, 11, 6, 0, 0, 1>(100000, 4000000, 16, MINUS);
      // The errors are even lower here, just 1.3% across these cases.

      testRepOp<uint32_t, 27, 6, 0, 0, 1>(5.31e9, 1e9, 1, PLUS);
      testRepOp<uint32_t, 27, 6, 0, 0, 1>(4.67e9, 5e9, 1, MINUS);

   }

   // 11ns/op
   testMult<uint16_t, 3, 6, 0, 0, 1>(n, 20);
   testMult<uint16_t, 11, 6, 0, 0, 1>(n, 20);
   testMult<uint16_t, 6, 10, 1, 1, 1>(n, 20);
   testMult<uint16_t, 8, 9, 0, 1, 0>(n, 20);
   testMult<uint32_t, 25, 7, 1, 1, 0>(n, 20);

   cout << (double)nconv << " conversions, " << (double)nop << " operations\n";
#ifdef TRACK
   cout << "# of randomized adjustments: " << nadj << " net effect=" 
        << diff/nadj << endl;
   double expmean = ((1ul << 63)-1) + 0.5;
   cout << "Mean of RNG " << sumr/nadj << ", error wrt to expected mean is " 
        << (1-(sumr/nadj)/expmean) << endl;
#endif
   // The reason for disappointing performance of randomized correction seems
   // to be that the RNG's mean is quite a bit off expectation --- an error
   // of 3e-5, which is comparable to the 
   nextr(1);

}
