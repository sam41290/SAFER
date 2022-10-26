#include <iostream>
#include "../GeoHistogram.h"

using namespace std;

#define NPOINTS 1000000

long iter, iter1;
int main(int argc, char *argv[]) {

   Histogram s; LongHistogram l;
   unsigned long r[NPOINTS];
   double avg=0;

   for (unsigned i=0; i < NPOINTS; i++) {
      r[i] = i*1000;//random()>>4;
      avg += r[i];
   }

   avg /= NPOINTS;

   double f;
   for (unsigned i=0; i < 1000; i++) {
      for (unsigned j=0; j < NPOINTS; j++) {
         //f = log(r[j]);
         //s.addPoint(r[j]);
         l.addPoint(r[j]);
      }         
   }

   // cout << f << endl; return 0;

   cout << "Correct mean: " << avg << endl;
   //s.print(cout);
   l.print(cout);
   //l.print(cout, true);

   // Timing results: 1.8ns/increment if you don't preserve mean
   // 3.5ns/incr with the faster version of MEAN_PRESERVATION option enabled.
   // If we work with float or double, then log takes 37ns per operation,
}
