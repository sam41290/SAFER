using namespace std;
#include "../FreqDistrib.h"

typedef FreqDistribLearnAlt<1ul<<4, 1ul<<8, 1ul<<12, 1ul<<16, 1ul<<20, 1ul<<24,
      1u<<28, 1ul<<32, 1ul<<36, 1ul<<40, 1ul<<44> FD;
typedef FreqDistribDetectAlt<1ul<<4, 1ul<<8, 1ul<<12, 1ul<<16, 1ul<<20, 1ul<<24,
      1u<<28, 1ul<<32, 1ul<<36, 1ul<<40, 1ul<<44> FDD;

long iter, iter1;
int main(int argc, char *argv[]) {
   cout << "Size of FreqDistribLearnAlt is " << sizeof(FD) << endl;
   cout << "Size of FreqDistribDetectAlt is " << sizeof(FDD) << endl;

   cout << "Long test\n";
   unsigned long n=random();
   unsigned long m=0;
   unsigned long k=0;
   //n *= random();
   //for (int r=0; r < 4; r++) {
      FD ic(n);
      FDD jc(n);
      for (unsigned i=0; i < 32; i++) {
         // Burst of length 1<<i, with one inc every tick during the burst
         for (unsigned long j=0; j < (1ul<<i); j++) {
            k += ic.inc(n);
            k += ic.inc(n);
            k += ic.inc(n);
            jc.inc(n);
            jc.inc(n);
            jc.inc(n);
            jc.inc(++n);
            k += ic.inc(n);
         }
         // Followed by a long idle period
         n += (1<<26);
         m += 4*(1ul<<i);
      }
      k += ic.inc(++n);
      jc.inc(n);
      k += ic.inc(n);
      //if (r==3) {
         jc.inc(n);
         ic.finalize(n);
         ic.print(cout, false, false);
         jc.finalize(n);
         jc.print(cout, false, false);

         cout << (m/1000000000) << "B increments performed, ";
         cout << ((k-m)/1000000) << "M propagated beyond the first bin\n";
         cout << "All operations executed once each in learning "
              << "and detection modes\n";
      //}
   //}
   // Takes about 32 seconds to run on Sekar's laptop 2/13/21 with g++ -O3,
   // and 38s with -O2. 
}
