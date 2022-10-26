#include <stdint.h>
inline constexpr unsigned ilog2(unsigned long l) { return 63 - __builtin_clzl(l); };

template<unsigned n2bins=64, unsigned n4bins=0, unsigned n8bins=0, 
         unsigned n16bins=0>
struct Geo24816Binner {
   constexpr static unsigned nbins = 1+n2bins+n4bins+n8bins+n16bins;
   static constexpr unsigned bin(uint64_t v) {
      if (v < 2) return v;
      unsigned logv = ilog2(v); 
      unsigned rv = logv;
      if (rv < n2bins) 
         return 1+logv; // 2 <= v < 2^n2b, rv=log2(v)+1
      rv = (logv-n2bins)/2; 
      // Invariant: rv = (log2(v)-n2b)/2
      // i.e., log2(v) = 2rv+n2b
      if (rv < n4bins) // log2(v) < 2n4b+n2b
         return 1+n2bins+rv; // 2^n2b <= v < 2^(n2b+2n4b)
      rv = (logv-n2bins-2*n4bins)/3;
      // Inv: rv = ((log2(v)-n2b)/2-n4b)
      if (rv < n8bins) 
         return 1+n2bins+n4bins+rv;
      rv = (logv-n2bins-2*n4bins-3*n8bins)/4;
      if (rv < n16bins) 
         return 1+n2bins+n4bins+n8bins+rv;
      return nbins-1;
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

template <typename ElemType, ElemType... Partitions>
struct IntervalBinner {
   inline static constexpr const ElemType start_[]={Partitions...};
   inline static const constexpr unsigned n=sizeof(start_)/sizeof(ElemType);
   static constexpr unsigned bin(ElemType v) {
      unsigned l=0, r = (15 < n-1 ? 15 : n-1);
      if (v >= start_[r]) {
         l=r;
         r=n-1;
         // Inv: start_[l] <= v  && (v < start_[r] || r==n-1&&v>start_[n-1])
         while (l+15 < r) {
           unsigned mid = (l+r)>>1;
            if (start_[mid] <= v)
               l = mid;
            else r=mid;
         }
      }
      // (v<start_[0]&&l==0||start_[l]<=v)&&(v<start_[r]||r==n-1&&v>start_[n-1])

      for (unsigned i=l; i <= r; i++)
         if (v < start_[i])
            return (i==0? i : i-1);
      return n-1;
   }

   static constexpr ElemType start(unsigned i) {      
      if (i < n)
         return start_[i];
      else return start_[n-1];
   }
};

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
chk2(1e12, 1e17, ib.n-1);

