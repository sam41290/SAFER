#include <iostream>
#include <stdlib.h>
#include <stdint.h>

using namespace std;


typedef unsigned /*long*/ t1;
typedef uint64_t /*__uint128_t*/ t2;

const t1 p = ((1ul<<31)-1); //(0ul)-59;

int main(int argc, char *argv[]) {
   unsigned long n = argc > 1? atol(argv[1]) : 1000;
   t1 r = (t1) random();
   t2 rv1 = (1<<30)+(1<<29);
   t2 rv2 = (1<<30)+(1<<29)+(1<<28);
   t2 rv3 = (1<<30)+(1<<29)+(1<<28)+(1<<27);
   t2 rv4 = (1<<30)+(1<<29)+(1<<28)+(1<<27)+(1<<26);
   for (unsigned long i=0; i < n; i++) {
      rv1 *= r; rv1 = rv1 % p;
      rv2 *= r; rv2 = rv2 % p;
      rv3 *= r; rv3 = rv3 % p;
      rv4 *= r; rv4 = rv4 % p;
   }
   cout << (t1)rv1 << ' ' << (t1)rv2 << ' ' << (t1)rv3 << ' ' << (t1)rv4;
}
