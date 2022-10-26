#include <iostream>
#include <stdlib.h>
using namespace std;

const unsigned p = (1u<<31)-1;

unsigned ap(unsigned a, unsigned b) {
  unsigned long rv = a;
  rv += b;
  if (rv >= p) rv -= p;
  return (unsigned)rv;
}

unsigned sp(unsigned a, unsigned b) {
   unsigned rv = (a > b)? a-b : b-a;
   if (rv >= p) rv -= p;
   return rv;
}

unsigned mp(unsigned a, unsigned b) {
   unsigned long rv = a;
   rv *= b;
   rv = (rv & ((1u<<31)-1)) + (rv >> 31);
   if (rv >= p) rv -= p;
   return rv;
}

int main(int argc, char *argv[]) {
   unsigned long n = argc > 1? atol(argv[1]) : 1000;
   unsigned long r = (unsigned long) random();
   unsigned rv1 = (1<<30)+(1<<29);
   unsigned rv2 = (1<<30)+(1<<29)+(1<<28);
   unsigned rv3 = (1<<30)+(1<<29)+(1<<28)+(1<<27);
   unsigned rv4 = (1<<30)+(1<<29)+(1<<28)+(1<<27)+(1<<26);
   for (unsigned long i=0; i < n; i++) {
      rv1 = mp(rv1, r);
      rv2 = mp(rv2, r);
      rv3 = mp(rv3, r);
      rv4 = mp(rv4, r);
   }
   cout << rv1 << ' ' << rv2 << ' ' << rv3 << ' ' << rv4;
}
