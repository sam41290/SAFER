#include <iostream>
#include <math.h>

using namespace std;

static unsigned long x=123456789, y=362436069, z=521288629;
unsigned long xorshf96(void) {          //period 2^96-1
   unsigned long t;
   x ^= x << 16;
   x ^= x >> 5;
   x ^= x << 1;

   t = x;
   x = y;
   y = z;
   z = t ^ x ^ y;
   return z;
}

unsigned long rand1() {
   static const unsigned long a = 6364136223846793005ul;
   static const unsigned long c = 1442695040888963407ul;
   static unsigned long r=1;

   r = a*r + c;
   return r;
}

double sum, err,toterr,neterr;
long ct;

unsigned long rand2() {
   static const unsigned long a = 6364136223846793005ul;
   static const unsigned long c = 1442695040888963407ul;
   static unsigned long r=1, r2=0;

   if (r2==0) {
      r = a*r + c;
      r2 = r;
   }
   unsigned long rv=r2 & ((1ul<<SHIFT)-1);
   r2 >>= SHIFT;
#ifdef MEASURE
   ct++;
   sum += rv;
#endif
   return rv;
}

unsigned short rand3() {
   static const unsigned short a=65533;
   static const unsigned short c=30031;
   static unsigned short r=1;

   r = a*r+c;
#ifdef MEASURE
   ct++;
   sum += r;
#endif
   return r;
}

char c[1<<16];

void tryr(long j) {
   ct=0;
   sum=0;
   while (j--) 
      rand2();
   cout << rand2();
#ifdef MEASURE
   err = (1-(sum/ct)/((1ul<<(SHIFT-1))-0.5));
   cout << "Average=" << sum/ct << ", error=" << err << endl;
#endif
}

int main(int argc, char *argv[]) {
   int npos=0, nneg=0; int ntries=10000;
   for (int i=0; i < ntries; i++) {
      tryr(random() % 524287);
      if (err < 0) nneg++;
      else npos++;
      toterr += fabs(err);
      neterr += err;
   }
   cout << "npos=" << npos << ", nneg=" << nneg 
        << ", net err=" << neterr << ", avg err=" << toterr/ntries << endl;
}
/* 
  unsigned long r1;
   double iters=(1<<16)*(1+((double)random()+random()+random())/65536/65536);
   long j = iters;
   int n=1<<16;
   long extra=0;
   while (j--) {
      r1 = rand3();
      unsigned short t = r1;
      if (c[t] == 0) {
         n--;
         c[t] = 1;
         if (n==0)
            cout << "c is filled, extra=" << extra << endl;
      }
      else {
         extra++;      
         //cout << t << " generated again\n";
      }
   }
   cout << r1 << endl;
   cout << "iters=" << iters << ", n=" << n << ", extra=" << extra << endl;
#ifdef MEASURE
   cout << "Average=" << sum/ct << ", error=" 
        << (1-(sum/ct)/((1ul<<(SHIFT-1))-0.5)) << endl;
#endif
}
*/

// The following test shows that multiplication on unsigned longs takes the
// exact same time as unsigned. Measured 1.3ns/multiplication. That is almost
// twice as fast as xorshf96. Adding a 64-bit modulo increases runtime it to
// 3.3ns. random() seems to be the slowest, at 6ns/call

/*
int main(int argc, char *argv[]) {

   static const unsigned long a = 6364136223846793005ul;
   static const unsigned long c = 1442695040888963407ul;
   unsigned long m = 0;
   m -= 59; // a prime

   //unsigned r=1;
   unsigned long r=1;

   for (unsigned i=0; i < 1000000000; i++)
      r = (a*r + c); // % m;
      //r += xorshf96();
      //r += random();

   cout << r << endl;
}
*/

// UPDATE: Using the commented out program below, we get 0.41ns/mult, no
// difference between int and long. Checked assembly code that all the
// multiplications are indeed being performed.

// UPDATE: float/double multiplication increases the cost to 0.56/.57ns.
// Conversions from or to int/long cost 0.7/1 ns.

// MORE UPDATE: Another commented out program below shows that double mult
// plus add takes about 0,5ns, float mult plus add takes 0.47ns, and a
// conversion between these formats takes 0.6ns

/*
#include <stdio.h>
#include <stdlib.h>

#define ASIZE (1<<25)
long ia[ASIZE];

int main(int argc, char* argv[]) {
   int n = (argc > 1)? atoi(argv[1]):10;

   long a = random();
   long b = random();
   long c = random();
   long d = random();
   long e = random();
   long f = 0;
   for (unsigned i=0; i < ASIZE; i++)
      ia[i] = random();

   for (unsigned j = 0; j < n; j++) {
      for (unsigned i=0; i < ASIZE; i++) {
         ia[i] = ia[i]*a - b;
         ia[i] = ia[i]*b - c;
         ia[i] = ia[i]*c - d;
         ia[i] = ia[i]*d - e;
         ia[i] = ia[i]*e - a;
         f += ia[i];
      }
   }

   printf("%g operations, result = %ld\n", 5.0*n*ASIZE, f);
}
*/
/*
#include <stdio.h>
#include <stdlib.h>

typedef float A;
//typedef double A;
typedef float B;
//typedef double B;

// Results of ./a.out 20 2
// A       B       Time
// double  double  1.93s
// double  float   2.02
// float   double  6s
// float   float   1.77
// NOTE: When B is float and A is double, Bs are all converted to double and
// then the operations are performed. But since Bs don't change inside the loop,
// the compiler can convert them into double once. Perhaps this is why this
// combination performs about the same as two other combinations. But when A 
// is float and B is double, A is converted to double first, then operations
// are performed, and the result converted back to float before storage. This
// means two conversions per operation, so we have about 7B conversions. This
// increases runtime by about 4s, i.e., about 0.6ns per conversion. Double
// multiplication plus addition takes only 0.5ns per operation, which reduces
// modestly to 0.47ns if everything is float.

#define ASIZE (1<<25)
A ia[ASIZE];

int main(int argc, char* argv[]) {
   int n = (argc > 1)? atoi(argv[1]):10;
   int m = (argc > 2)? atoi(argv[2]):0;
   int cc=0;

   for (int i=0; i< m; i++) cc += random();
   B a = random(); a = a/RAND_MAX;
   B b = random(); b = b/RAND_MAX;
   B c = random(); c = c/RAND_MAX;
   B d = random(); d = d/RAND_MAX;
   B e = random(); e = e/RAND_MAX;
   B f = 0;
   for (unsigned i=0; i < ASIZE; i++) {
      ia[i] = random();
      ia[i] = ia[i]/RAND_MAX;
   }

   for (unsigned j = 0; j < n; j++) {
      for (unsigned i=0; i < ASIZE; i++) {
         ia[i] = ia[i]*a + b;
         ia[i] = ia[i]*b - c;
         ia[i] = ia[i]*c + d;
         ia[i] = ia[i]*d - e;
         ia[i] = ia[i]*e + a;
      }
   }

   int k=0, l=0; double x;
   for (unsigned i=0; i < ASIZE; i++) {
      if (ia[i] < 1e-10) k++;
      else if (ia[i] > 1e10) l++;
      f += ia[i];
   }

   printf("%g operations, average = %g\n", 5.0*n*ASIZE, (double)f/ASIZE);
   printf("%g fraction of these have become very small, %g too large, cc=%d\n", 
          ((double)k)/ASIZE, ((double)l)/ASIZE, cc);
}
*/
