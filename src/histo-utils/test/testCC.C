#include "CompactCounter.h"
#include <iostream>
#include <math.h>

static int n;

template <class C, unsigned M, unsigned E>
void testBasic(CompactCounter<C, M, E>& a, int x, uint64_t y, double d) {
   cout << "********** Basic tests: " << ++n << "\n";
   a=x;
   cout << CompactCounter<C, M, E>::maxf() << endl;
   cout << a << " " << x << " " << (a == x) << " " << (a != x) << endl;
   a=y;
   cout << a << " " << y << " " << (a == y) << " " << (a != y) << endl;
   a=d;
   cout << a << " " << d << " " << (d-(double)a)/d << endl;
   uint64_t b = 1ul<<(8*sizeof(C)-1);
   a = b;
   cout << a << " " << b << " " << (a == b) << " " << (a != b) << endl;
   b = 1ul<<(min(63ul, 8*sizeof(C)));
   a = b;
   cout << a << " " << b << " " << (a == b) << " " << (a != b) << endl;
   a=(1ul<<63);
   cout << a << " " << (1ul<<63) << " " << (a == (1ul<<63)) << " " << (a != (1ul<<63)) << endl;
   for (auto z: {1e2, 1e21, 1e22, 1e150, 1e154, 1e156}) {
      a=z;
      cout << a << " " << z << " " << (a == z) << " " << (a != z) << endl;
   }
}

long ct;
template <class C, unsigned M, unsigned E>
void testInc(CompactCounter<C, M, E>& a, long j, long k) {
   CompactCounter<C, M, E> b=a;
   cout << "Incr by " << j << ": ";
   while (k--) {
      a=b;
      for (long i=0; i < j; i++)
         ++a;
      ct += j;
   }
   cout << "result " << a << ", error=" << (1 - ((double)a)/j) << endl;
}

template <class C, unsigned M, unsigned E>
void testDec(CompactCounter<C, M, E>& a, long j, long k) {
   cout << "Decr by " << j << ": ";
   while (k--) {
      a=(uint64_t)(2*j);
      for (long i=0; i < j; i++)
         --a;
      ct += j;
   }
   cout << "result " << a << ", error=" << (((double)a)-j)/j << endl;
}

int
main(int argc, char* argv[]) {
   CompactCounter<uint16_t, 10, 6> a;
   typedef CompactCounter<uint32_t, 26, 6> B;
   B b;
   typedef CompactCounter<uint64_t, 53, 9> C;
   C c;
   //CompactCounter<uint64_t, 52, 11> d; // assertion fail, EBITS too high
   //CompactCounter<uint64_t, 53, 10> e; // assertion fail, EBITS too high

   //CompactCounter<int16_t,  10, 6> f;  // assertion fail, must be unsigned
   //CompactCounter<uint16_t, 11, 6> g;  // assertion fail, needs too many bits
   //CompactCounter<int32_t,  26, 6> h;  // assertion fail, must be unsigned
   //CompactCounter<uint32_t, 27, 6> i;  // assertion fail, needs too many bits
   //CompactCounter<int64_t,  11, 6> j;  // assertion fail, must be unsigned
   //CompactCounter<uint64_t, 54, 6> k;  // assertion fail, needs too many bits

   cout << "sizeof(a)=" << sizeof(a) << endl;
   cout << "sizeof(b)=" << sizeof(b) << endl;
   cout << "sizeof(c)=" << sizeof(c) << endl;

   testBasic(a, 4, 75787798797ul, 1.1111111e18);
   testBasic(b, 473, 75787798ul, 1.1111111e18);
   testBasic(c, 473, 7578779899999999999ul, 1.11111111111111e25);

   a=4;
   a.inc(4);
   b=473;
   b.inc(40);
   c=11733322423232ul;
   c.inc(400);

   cout << "a=" << a << " b=" << b << " c=" << c << endl;

   a=0;
   b=0;
   c=0;

   cout << "\nTesting increment/decrement:\n";

   testInc(a, 8e6, 1); // 1.85ns/1.2 per inc (-O2/-O3)
   testInc(b, 5.31e9, 1); // 1.95ns per inc with -O2, 0.7ns with -O3
   //testInc(b, 3.37e9, 1); // 1.95ns per inc with -O2, 0.7ns with -O3
   //testInc(a, 3.5e4, 100000); // 1.85ns/1.2 per inc (-O2/-O3)
   //testInc(b, 2e9, 3); // 1.95ns per inc with -O2, 0.7ns with -O3
   testInc(c, 5e9, 1); // 1.85ns/1.3ns per inc (-O1/-O3)

   // testDec(a, 3.5e4, 100000); // 2.05ns/1.8ns per dec (-O2/-O3)
   testDec(a, 17e6, 1); 
   //testDec(b, 2e9, 3); // 1.75ns per decc with -O2, 1ns with -O3
   testDec(b, 4.67e9, 1);
   //testDec(b, 2.79e9, 1);
   testDec(c, 5e9, 1); // 1.75ns/0.7ns per inc (-O1/-O3)
   /* Interestingly, g++ is more than 2x faster than clang++ */

   cout << "Performed " << (double)ct << " operations\n";
   // Total time 25.5/54 sec with O3/O2 (81/76 seconds with clang++)
   // (The best time coresponds to 0.87ns/operation.)
   // Mysteriously increased to 30s in one day (2/8/21)
}
