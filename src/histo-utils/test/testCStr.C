#include <stdlib.h>
#include <malloc.h>
#include <thread>

#include "cstring.h"
#include "GeoHistogram.h"

#define sz 8
typedef CStringImpl<sz> CString;

GeoHistogram<size_t, 16, 32, 1, 1> totalloc;
atomic<unsigned long> allocsize, freesize, nops;
unsigned long maxsize;
bool do_cs, do_s;
unsigned c=10; unsigned m=71; unsigned n=400; unsigned t=1;
unsigned mxlen=0;

CString **csd, *css;
string **sd, *ss;

void * operator new(size_t size) { //_THROW1(_STD bad_alloc)
   void *p = malloc(size);
   unsigned siz = malloc_usable_size(p)+8;
   if (t == 1) totalloc.addPoint(siz);
   allocsize += siz;
   maxsize = max(allocsize-freesize, maxsize);
   return p;
}

void operator delete(void *p) {
   freesize += malloc_usable_size(p)+8;
   free(p);
}

void operator delete[](void *p) {
   freesize += malloc_usable_size(p)+8;
   free(p);
}

unsigned mrandom() {
   static atomic<unsigned> r;
   static const unsigned a = 1103515245;
   static const unsigned c = 12345;
   unsigned rr = r;
   rr = rr*a + c;
   r = rr;
   return rr;
}

unsigned char myrandom() {
   static int offset, r;
   if (offset == 0)
      r = mrandom();
   unsigned char rv = (r & 0xff);
   r = (r>>8);
   offset = ((offset+1) & 0x3);
   return rv;
};

const char* genstr(unsigned l) {
   static unsigned char rv[100000];
   assert(l < sizeof(rv));
   for (unsigned i=0; i < l; i++)
      rv[i] = myrandom();
   return (char*)rv;
}

void verify(CString& cs, string& s) {
   assert(s.size() == cs.size());
   string tp(cs.data(), cs.size());
   for (unsigned j=0; j < s.size(); j++)
      assert(tp[j] == s[j]);
}

void doInit(unsigned i, const char* sss, unsigned l) {
   if (do_cs)
      css[i] = CString(sss, l);
   if (do_s)
      ss[i] = string(sss, l);
   if (do_cs && do_s)
      verify(css[i], ss[i]);
}

void usage(const char* prog) {
   cout << "Usage: " << prog << "[-c] [-s] N C L [T]\n"
        << "-c: use CString, -s: use string, "
        << "Generates 3C random strings of max length L, performs N "
        << "operations on them using T threads\n"
        << "Use C >= 0.1N to ensure strings don't get too long due to "
        << "concatenations.\n Enable one of -c or -s; enable both to test "
        << "CString\n";
   exit(1);
}

void do_work(CString* cs, string *s) {
   CString *csn=nullptr; string *sn=nullptr;
   if (t > 1) {
      if (do_cs) csn = new CString [3*c+1]; 
      if (do_s) sn = new string [3*c+1];
      for (unsigned i=0; i < 3*c+1; i++) {
         if (do_cs) csn[i] = cs[i];
         if (do_s) sn[i] = s[i];
      }
      nops += n;
   }
   else {
      csn = cs; sn = s;
   }

   for (unsigned i=0; i < n; i++) {
      unsigned j = mrandom() % (3*c+1);
      unsigned k = mrandom() % (3*c+1);
      unsigned op = (j+k) % 5;
      if (op < 4) { // 4/5 prob of asg, 1/5 prob of concatenation
         if (do_cs)
            csn[j] = csn[k];
         if (do_s)
            sn[j] = sn[k];
      }
      else {
         if (do_cs) {
            csn[j] += csn[k];
            if (csn[j].size() > mxlen) mxlen = csn[j].size();
         }
         if (do_s) {
            sn[j]  += sn[k];
            if (sn[j].size() > mxlen) mxlen = sn[j].size();
         }
      }
   }

   if (do_cs && do_s)
      for (unsigned i=0; i < 3*c+1; i++)
         verify(csn[i], sn[i]);

   if (t > 1) {
      if (csn) delete [] csn;
      if (sn) delete [] sn;
   }
}

int main(int argc, const char* argv[]) {
   const char* prog = argv[0];
   while (argc > 1 && *argv[1] == '-') {
      if (argv[1][1] == 'c')
         do_cs = true;
      else if (argv[1][1] == 's')
         do_s = true;
      else usage(prog);
      argc--; argv = &argv[1];
   };
   if (argc != 4 && argc != 5)
      usage(prog);
   if (argc > 1)
      n = atoi(argv[1]);
   if (argc > 2)
      c = atoi(argv[2]);
   if (argc > 3)
      m = atoi(argv[3]);
   if (argc > 4)
      t = atoi(argv[4]);

   if (do_cs) css = new CString [3*c+1]; 
   if (do_s) ss = new string [3*c+1];

   unsigned l;
   for (unsigned i=0; i < c; i++) {
      l = mrandom() % (1+sz/2);
      doInit(3*i, genstr(l), l);
      l = mrandom() % (1+sz);
      doInit(3*i, genstr(l), l);
      l = mrandom() % (m+1);
      doInit(3*i+2, genstr(l), l);
   }
   doInit(3*c, genstr(l), l);

   if (t > 1) {
      vector<thread> thrs;
      for (unsigned k=0; k < t; k++)
         thrs.push_back(thread(do_work, css, ss));
      for (unsigned k=0; k < t; k++)
         thrs[k].join();
   }
   else {
      nops = n;
      do_work(css, ss);
   }

   if (do_cs) delete [] css;
   if (do_s) delete [] ss;

   cout << "Done after " << nops/1e06 << "M operations on " << (float)(3*c) 
        << " strings, max initial len=" << m 
        << ", maxlen=" << mxlen << endl;
   cout << "Total allocation=" << (allocsize+500000)/1000000 << "M, max use=" 
        << (maxsize+500000)/1000000 << "M, still in use " 
        << (allocsize-freesize+500000)/1000000 << "M\n";
   if (t==1)
      totalloc.print(cout);
}
/*
./a.out 10000000 1000000 31
Done: 1e+07 operations on 3e+06 strings, max initial len=31, maxlen=1602 (sz=8)
Done: 1e+07 operations on 3e+06 strings, max initial len=31, maxlen=2353 (sz=16)
*/
