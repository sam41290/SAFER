#define MFU_DBG // No overhead, just ensures that # of operations is tracked
#include "MFUTab.h"
#include "DecayMFUTab.h"
#include <stdlib.h>

unsigned inline myrandom() {
   static const unsigned a = 1103515245;
   static const unsigned c = 12345;
   static unsigned r;
   r = a*r + c;
   return r;
}

bool dbg=0;
long shrct, insct, rmct, nvisit;
int logLevel=WARNLEVEL;

void trymfur(unsigned maxSz, unsigned actualSz, unsigned c) {
   MFUTable<unsigned, unsigned> 
      tt(maxSz, [](unsigned k, MFUData<unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ':' << d.data() << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b], b);
      rv += b;
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         rv+=b; tt.insert(t[b], b);
      }
   }
   cout << "trymfur done after " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, hit=" << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << ((2.0*rv)/c)/actualSz << endl;

   delete [] t;
}

void trymfuinit(unsigned maxSz, unsigned actualSz, unsigned c) {
   MFUTable<unsigned, unsigned, unsigned> 
      tt(maxSz, [](unsigned short k, MFUData<unsigned, unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ':' << d.data() << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b], b);
      rv += b;
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         rv+=b; tt.insertWithCount(t[b], b, myrandom());
      }
   }
   cout << "trymfuinit done after " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, hit=" << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << rv;

   delete [] t;
}

void trymfurset(unsigned maxSz, unsigned actualSz, unsigned c) {
   MFUSet<unsigned> 
      tt(maxSz, [](unsigned short k, MFUData<MFUVoid, unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b]);
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         tt.insert(t[b]);
      }
   }

   tt.visitAll([rv] (unsigned k, unsigned c) mutable { rv += k*c;});

   cout << "trymfurset done: " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, " << nvisit << " visits, hit=" 
        << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << rv;

   delete [] t;
}

void trymfurdecay(unsigned maxSz, unsigned actualSz, unsigned c,
                  long dcgen, double dcrate) {
   DecayMFUTable<unsigned, unsigned> 
      tt(maxSz, dcrate, dcgen, 0, [](unsigned k, MFUData<unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ':' << d.data() << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   long clock=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b], b, clock++);
      rv += b;
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         rv+=b; tt.insert(t[b], b, clock++);
      }
   }
   cout << "trymfur done after " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, hit=" << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << ((2.0*rv)/c)/actualSz;

   delete [] t;
}

void trymfuinitdecay(unsigned maxSz, unsigned actualSz, unsigned c,
                  long dcg, double dcr) {
   DecayMFUTable<unsigned, unsigned, unsigned> 
      tt(maxSz, dcr, dcg, 0, 
         [](unsigned short k, MFUData<unsigned, unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ':' << d.data() << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   long clock=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b], b, clock++);
      rv += b;
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         rv+=b; tt.insertWithCount(t[b], b, myrandom(), clock++);
      }
   }
   cout << "trymfuinit done after " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, hit=" << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << rv;

   delete [] t;
}

void trymfursetdecay(unsigned maxSz, unsigned actualSz, unsigned c,
                  long dcg, double dcr) {
   DecayMFUSet<unsigned> 
      tt(maxSz, dcr, dcg, 0,
         [](unsigned short k, MFUData<MFUVoid, unsigned> d, bool b) {
            if (dbg) cout << "shrink called " << k << ' ' 
                          << d.count() << ' ' << b << endl;
            if (b) rmct++;
            else shrct++;
         });

   unsigned *t = new unsigned [actualSz];
   for (unsigned k=0; k < actualSz; k++)
      t[k] = k;

   for (unsigned k=0; k < actualSz; k++) {
      unsigned i = myrandom() % actualSz;
      unsigned j = myrandom() % actualSz;
      swap(t[i], t[j]);
   }

   unsigned fac=4; long rv=0;
   long clock=0;
   for (unsigned k=0; k < c/fac; k++) {
      unsigned b = myrandom() % actualSz;
      tt.insert(t[b], clock++);
      for (unsigned j=0; j < fac-1; j++) {
         b = myrandom() % min(maxSz-1, actualSz);
         tt.insert(t[b], clock++);
      }
   }

   tt.visitAll([rv] (unsigned k, unsigned c) mutable { rv += k*c;});

   cout << "trymfurset done: " << insct/1.0e3 << "K inserts, " 
        << shrct/1.0e3 << "K countAdjusts, "
        << rmct/1.0e3 << "K removes, " << nvisit << " visits, hit=" 
        << tt.hitRate() << "\n";
   if (dbg) tt.print(cout);
   cout << rv;

   delete [] t;
}

int main(int argc, char *argv[]) {
   struct T { 
      char a; unsigned u; char *s; double d;
      T() {a = 0; u = 0; s = nullptr; d = 0.;};
   };
   MFUData<unsigned short> m1(0);
   MFUData<int> m2(0);
   MFUData<long> m3(0l);
   MFUData<char*> m4(nullptr);
   T t;
   MFUData<T> m5(t);
   MFUData<T*> m6(nullptr);
   MFUData<unsigned short, int> m7(0);
   MFUData<unsigned char, unsigned char> m8(0);
   MFUSet<int> xxxx(100);

   cout << "m1: " << sizeof(m1) << " ";
   cout << "m2: " << sizeof(m2) << " ";
   cout << "m3: " << sizeof(m3) << " ";
   cout << "m4: " << sizeof(m4) << " ";
   cout << "m5: " << sizeof(m5) << " ";
   cout << "m6: " << sizeof(m6) << " ";
   cout << "m7: " << sizeof(m7) << " ";
   cout << "m8: " << sizeof(m8) << endl;
   cout << "xxxx: " << sizeof(xxxx) << endl;

   const char* cmdname = argv[0];
   if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'd') {
      dbg = true;
      argc--;
      argv = &argv[1];
   }
   bool useset=false;
   if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 's') {
      useset = true;
      argc--;
      argv = &argv[1];
   }
   bool useinit=false;
   if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'c') {
      useinit = true;
      argc--;
      argv = &argv[1];
   }
   bool usedecay=false;
   if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'D') {
      usedecay = true;
      argc--;
      argv = &argv[1];
   }

   if ((!usedecay && argc == 4) || (usedecay && argc == 6)) {
      if (!usedecay) {
         if (useset)
            trymfurset(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]));
         else if (useinit)
            trymfuinit(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]));
         else
            trymfur(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]));
      }
      else {
         long g = atol(argv[4]);
         double r = atof(argv[5]); 
         if (useset)
            trymfursetdecay(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), g, r);
         else if (useinit)
            trymfuinitdecay(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), g, r);
         else
            trymfurdecay(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), g, r);
      }
   }
   else 
      cout << "Usage: " << cmdname 
           << " [-d] [-s|-c] [-D] tableSz #ofKeys #ofInserts"
           << " [decaygen decayrate]\n"
           << " -d: turn debug print outputs\n"
           << " -s: test Set rather than Table\n"
           << " -c: test Table with initial count\n"
           << " -D: test DecayMFU rather than MFU\n";

   // Obtained performance w/compile: g++ -I.. -O2 -std=c++17 testMFU.C
   // For inserts only: use actualsize = 95% of capacity
   // ex: time ./a.out  30,000,000 29,000,000 100,000,000
   //     m1: 4 m2: 8 m3: 16 m4: 8 m5: 32 m6: 8 m7: 8 m8: 2
   //     xxxx: 112
   //     trymfur done after 100000K inserts, 0K countAdjusts, 0K removes, hit=0.7189
   //     1449027736399168
   //     real	1m10.311s
   //     user	1m8.597s
   //     sys	0m1.505s
   //
   // For insert and deletes: use actual size = 200% of capacity
   // ex: time ./a.out  30000000 60000000 200000000
   //     m1: 4 m2: 8 m3: 16 m4: 8 m5: 32 m6: 8 m7: 8 m8: 2
   //     xxxx: 112
   //     trymfur done after 200000K inserts, 0K countAdjusts, 47551.5K removes, hit=0.618068
   //     3743128945182015
   //     real	3m20.652s
   //     user	3m19.214s
   //     sys	0m1.432s
   //
   //    TabSz --- Time per insert (ns) --- Time per remove (ns)
   //    30	15    145
   //    3K     15    196
   //    30K    30    290
   //    300K  220   1140
   //    3M    465   1053
   //    30M   680   1280
}
