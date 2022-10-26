#ifndef HISTO_BINNER_H
#define HISTO_BINNER_H

template<unsigned n2bins=64, unsigned n4bins=0, unsigned n8bins=0, 
         unsigned n16bins=0>
struct Geo24816Binner {
   static constexpr unsigned nbins() { return 1+n2bins+n4bins+n8bins+n16bins;};
   static constexpr unsigned bin(uint64_t v) {
      if (v < 2) return v;
      unsigned logv = ilog2(v); 
      unsigned rv = logv;
      if (rv < n2bins) 
         return 1+logv; // 2 <= v < 2^n2b, rv=log2(v)+1
      rv = (logv-n2bins)/2; 
      if (rv < n4bins) // log2(v) < n2b+2n4b
         return 1+n2bins+rv; // 2^n2b <= v < 2^(n2b+2*n4b)
      rv = (logv-n2bins-2*n4bins)/3;
      if (rv < n8bins) // log2(v) < logv+n2b+2n4b+3n8b
         return 1+n2bins+n4bins+rv;
      rv = (logv-n2bins-2*n4bins-3*n8bins)/4;
      if (rv < n16bins) // log2(v) < logv+n2b+2n4b+3n8b+4n16b
         return 1+n2bins+n4bins+n8bins+rv;
      return nbins()-1;
   };
   // Example to check: 0-0 1-1 2-3 4-7 8-31 32-127 128-2047 2048-32767
   // Zero bin is not counted, so n2bins=3, n4bins=2, n8bins=0, n16bins=2
   static constexpr uint64_t start(unsigned i) {
      uint64_t rv=0;
      if (i > 0) {
         rv=1;
         i--;
         if (i < n2bins)
            rv <<= i;
         else {
            rv <<= n2bins;
            i -= n2bins;
            if (i < n4bins)
               rv <<= 2*i;
            else {
               rv <<= 2*n4bins;
               i -= n4bins;
               if (i < n8bins)
                  rv <<= 3*i;
               else {
                  rv <<= 3*n8bins;
                  i -= n8bins;
                  if (i < n16bins)
                     rv <<= 4*i;
                  else rv <<= 4*n16bins;
               }
            }
         }
      }
      return rv;  
   };
};

template <unsigned n2bins, unsigned n4bins, unsigned n8bins, unsigned n16bins>
using GeoHistogramNU = Histogram<Geo24816Binner<n2bins,n4bins,n8bins,n16bins>>;

using UnsignedHistogram = Histogram<Geo24816Binner<31,0,0,0>,unsigned,unsigned>;
using LongHistogram = Histogram<Geo24816Binner<63,0,0,0>,uint64_t,uint64_t>;

/*
// We can define a GeoHstogram with a uniform ratio 2^(real_val). The bin()
// function will need a division, while start() will also be somewhat complex.
// A simpler approach is to generate the starting points into a static array
// and then use IntervalBinner
template <unsigned NBINS, uint64_t range>
struct UniformGeoBinner {
   static constexpr unsigned bin(uint64_t v) {
   };

   static constexpr uint64_t start(unsigned i) {
   };
};
*/

template <class ElemType, class Partitions>
struct IntervalBinnerHelper {
   static constexpr unsigned bin(ElemType v) {
      unsigned l=0, r = (15 < Partitions::n-1 ? 15 : Partitions::n-1);
      if (v >= Partitions::start[r]) {
         l=r;
         r=Partitions::n-1;
         // Inv: start[l] <= v  && (v < start[r] || r==n-1&&v>start[n-1])
         while (l+15 < r) {
           unsigned mid = (l+r)>>1;
            if (Partitions::start[mid] <= v)
               l = mid;
            else r=mid;
         }
      }
      // (v<start[0]&&l==0||start[l]<=v)&&(v<start[r]||r==n-1&&v>start[n-1])

      for (unsigned i=l; i <= r; i++)
         if (v < Partitions::start[i])
            return (i==0? i : i-1);
      return Partitions::n-1;
   }

   static constexpr ElemType start(unsigned i) {      
      if (i < Partitions::n)
         return Partitions::start[i];
      else return Partitions::start[Partitions::n-1];
   }

   static constexpr unsigned nbins() { return Partitions::n; };
};

template <class ElemType, ElemType... Partitions>
struct IntervalBinnerHelper2 {
   inline static constexpr const ElemType start[]={Partitions...};
   inline static const constexpr unsigned n =sizeof(start)/sizeof(ElemType);
};

template <class ElemType, ElemType... Partitions>
using IntervalBinner = 
 IntervalBinnerHelper<ElemType, IntervalBinnerHelper2<ElemType, Partitions...>>;

template <class ElemType, ElemType... Partitions> 
using SimpleHistogram = Histogram<IntervalBinner<ElemType, Partitions...>>;

#ifdef TEST_Binner
Geo24816Binner<3,2,0,2> tt;
static_assert(tt.start(0)==0, "no");
static_assert(tt.start(1)==1, "no");
static_assert(tt.start(2)==2, "no");
static_assert(tt.start(3)==4, "no");
static_assert(tt.start(4)==8, "no");
static_assert(tt.start(5)==32, "no");
static_assert(tt.start(6)==128, "no");
static_assert(tt.start(7)==2048, "no");
static_assert(tt.start(8)==32768, "no");
static_assert(tt.start(9)==32768, "no");
static_assert(tt.start(10000)==32768, "no");
static_assert(tt.bin(0)==0, "no");
static_assert(tt.bin(1)==1, "no");
static_assert(tt.bin(2)==2, "no");
static_assert(tt.bin(3)==2, "no");
static_assert(tt.bin(4)==3, "no");
static_assert(tt.bin(7)==3, "no");
static_assert(tt.bin(8)==4, "no");
static_assert(tt.bin(31)==4, "no");
static_assert(tt.bin(32)==5, "no");
static_assert(tt.bin(127)==5, "no");
static_assert(tt.bin(128)==6, "no");
static_assert(tt.bin(1024)==6, "no");
static_assert(tt.bin(2047)==6, "no");
static_assert(tt.bin(2048)==7, "no");
static_assert(tt.bin(8000)==7, "no");
static_assert(tt.bin(17000)==7, "no");
static_assert(tt.bin(31000)==7, "no");
static_assert(tt.bin(10000000)==7, "no");

Geo24816Binner<0, 11, 6, 2> t1;
static_assert(t1.start(0)==0, "no");
static_assert(t1.start(1)==1, "no");
static_assert(t1.start(2)==4, "no");
static_assert(t1.start(3)==16, "no");
static_assert(t1.start(4)==64, "no");
static_assert(t1.start(5)==256, "no");
static_assert(t1.start(6)==1024, "no");
static_assert(t1.start(7)==4096, "no");
static_assert(t1.start(8)==(1<<14), "no");
static_assert(t1.start(9)==(1<<16), "no");
static_assert(t1.start(10)==(1<<18), "no");
static_assert(t1.start(11)==(1<<20), "no");
static_assert(t1.start(12)==(1<<22), "no");
static_assert(t1.start(13)==(1<<25), "no");
static_assert(t1.start(14)==(1<<28), "no");
static_assert(t1.start(15)==(1ul<<31), "no");
static_assert(t1.start(16)==(1ul<<34), "no");
static_assert(t1.start(17)==(1ul<<37), "no");
static_assert(t1.start(18)==(1ul<<40), "no");
static_assert(t1.start(19)==(1ul<<44), "no");
static_assert(t1.start(1000)==(1ul<<48), "no");
static_assert(t1.bin(0)==0, "no");
static_assert(t1.bin(1)==1, "no");
static_assert(t1.bin(2)==1, "no");
static_assert(t1.bin(3)==1, "no");
static_assert(t1.bin(4)==2, "no");
static_assert(t1.bin(7)==2, "no");
static_assert(t1.bin(15)==2, "no");
static_assert(t1.bin(16)==3, "no");
static_assert(t1.bin(63)==3, "no");
static_assert(t1.bin(64)==4, "no");
static_assert(t1.bin(255)==4, "no");
static_assert(t1.bin(256)==5, "no");
static_assert(t1.bin(1023)==5, "no");
static_assert(t1.bin(1024)==6, "no");
static_assert(t1.bin(4095)==6, "no");
static_assert(t1.bin(4096)==7, "no");
#define chk(n,m) static_assert(t1.bin((1ul<<n)-1)==m-1&&t1.bin(1ul<<n)==m, "no")
chk(14, 8);
chk(16, 9);
chk(18, 10);
chk(20, 11);
chk(22, 12);
chk(25, 13);
chk(28, 14);
chk(31, 15);
chk(34, 16);
chk(37, 17);
chk(40, 18);
chk(44, 19);
#undef chk
static_assert(t1.bin(1ul<<56)==19, "no");

IntervalBinner<long, 1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 260, 270, 280, 290, 300, 310, 320, 330, 340, 350, 360, 370, 380, 390, 400, 410, 420, 430, 440, 450, 460, 470, 480, 490, 500, 1000, 100000, 10000000, 1000000000000l> ib;

static_assert(ib.start(0)==1, "no");
static_assert(ib.start(1)==10, "no");
static_assert(ib.start(2)==20, "no");
static_assert(ib.start(10)==100, "no");
static_assert(ib.start(51)==1000, "no");
static_assert(ib.start(52)==100000, "no");
static_assert(ib.start(53)==10000000, "no");
static_assert(ib.start(54)==1000000000000l, "no");
static_assert(ib.start(55)==1000000000000l, "no");
static_assert(ib.start(60)==1000000000000l, "no");

static_assert(ib.bin(-100)==0, "no");
static_assert(ib.bin(1)==0, "no");
static_assert(ib.bin(9)==0, "no");
#define chk2(a, b, c) static_assert(ib.bin(a)==c && ib.bin(b)==c, "no")
#define chk22(a,c) chk2(a, a+9, c)
#define chk5(a,c) \
  chk22(a,c);chk22(a+10,c+1);chk22(a+20,c+2);chk22(a+30,c+3);chk22(a+40,c+4)
#define chk10(a,c) chk5(a,c); chk5(a+50,c+5)
chk10(10,1);
chk10(110, 11);
chk10(210, 21);
chk10(310, 31);
chk10(410, 41);
chk2(500, 999, 50);
chk2(1000, 99999, 51);
chk2(100000, 9999999, 52);
chk2(10000000, 999999999999l, 53);
chk2(1e12, 1e17, ib.nbins()-1);
#undef chk2
#undef chk22
#undef chk5
#undef chk10
#endif

#endif
