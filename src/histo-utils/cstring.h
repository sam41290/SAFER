#ifndef CSTRING_H
#define CSTRING_H

#include <atomic>
#include <mutex>
#include "Base.h"
#include "STLutils.h"

//
// Space-efficient reference-counted implementation of string buffer, providing
// read-only access to contents. Has 4-bytes overhead in the typical case, which
// increases to 8 bytes to support high capacities (4GB) and/or high reference
// counts (32M). For MT-safety, use a lock for reference count modifications and
// the destructor.
//

class CRefCtBuf { // max size 4GB, sizeof(CRefCtBuf) is 2^{n/2} for 8 <= n <= 64
 private:
   uint32_t base_;
   union {
      char data_[12]; // variable size
      struct {
         uint32_t size_;
         char data_[8];
      } ext_;
   };

#ifdef MT
   static mutex lk[8];
#endif

   bool isExtRep() const { return getbfs(base_, 0, mask(1)); };
   void extRep(bool e) { setbfs(base_, 0, mask(1), e); };

   unsigned capBits() const { return getbfs(base_, 1, mask(6)); };
   void capBits(unsigned char b) { setbfs(base_, 1, mask(6), b); };

   void lock() {
#ifdef MT
      long l = (long)this;
      l = (l ^ (l>>9)) & 0x7;
      lk[l].lock();
#endif
   }

   void unlock() {
#ifdef MT
      long l = (long)this;
      l = (l ^ (l>>9)) & 0x7;
      lk[l].unlock();
#endif
   }

   unsigned maxRefCount() const {
      if (isExtRep())
         return mask(25);
      else return mask(9);
   };

   unsigned refCount() const {
      if (isExtRep())
         return getbfs(base_, 7, mask(25));
      else return getbfs(base_, 7, mask(9));
   };
   void refCount(unsigned refc) {
      if (isExtRep())
         setbfs(base_, 7, mask(25), refc);
      else setbfs(base_, 7, mask(9), refc);
   };

   void size(unsigned s) {
      if (isExtRep())
         ext_.size_ = s;
      else setbfs(base_, 16, mask(16), s);
   };

   char* data(unsigned i=0) {
      //assert(i < size()); 
      return (isExtRep()? &ext_.data_[i] : &data_[i]);
   }

   static unsigned toCapacity(unsigned char cap) {
      unsigned rv; 
      rv = (16 << (cap >> 1));
      if (cap & 0x1) rv += (rv >> 1); // Multiply by 1.5 instead of sqrt(2)
      return rv;
   }

   static unsigned char toCap(unsigned capacity) {
      if (capacity < 16) capacity = 16;
      unsigned char rv = (ilog2(capacity>>4) << 1);
      unsigned capacity1 = (16 << (rv>>1));
      if (capacity1 >= capacity)
         return rv;
      else if (capacity1 + (capacity1 >> 1) >= capacity)
         return rv+1;
      else return rv+2;
   }

   unsigned capacity() const  
      { return toCapacity(capBits()) - (isExtRep()? 8 : 4); };
   void capacity(unsigned c) 
      { capBits(toCap(c + (isExtRep()? 8 : 4))); };
      
   CRefCtBuf() { extRep(false); refCount(1); size(0); capacity(0); };

 public:
   CRefCtBuf(const CRefCtBuf&) = delete;

   unsigned decRefCount()
      { lock(); unsigned rv = refCount()-1; refCount(rv); unlock(); return rv; };

   bool incRefCount() { 
      lock();
      unsigned rv = refCount()+1; 
      if (rv  >= maxRefCount()) {
         unlock();
         return false;
      }
      refCount(rv); unlock();
      return true; 
   };

   unsigned size() const {
      if (isExtRep())
         return ext_.size_;
      else return getbfs(base_, 16, mask(16));
   };

   const char* data(unsigned i=0) const {
      return const_cast<CRefCtBuf*>(this)->data(i);
   }

   static CRefCtBuf* alloc(unsigned initCapacity) {
      unsigned sz = toCapacity(toCap(initCapacity+4));
      assert(sz >= initCapacity+4);
      bool ext = (sz > 65536);
      if (ext) sz = toCapacity(toCap(initCapacity+8));
      CRefCtBuf* rv = (CRefCtBuf*) new char[sz];
      rv->extRep(ext); rv->refCount(1); rv->size(0); rv->capacity(initCapacity); 
      return rv;
   };

   static CRefCtBuf* alloc(const char* s, unsigned len, unsigned cap=0) {
      if (cap == 0) cap=len;
      CRefCtBuf* rv = alloc(cap);
      memcpy(rv->data(), s, len);
      rv->size(len);
      return rv;
   }

   //static CRefCtBuf* clone(CRefCtBuf* old, unsigned newCapacity=0)
   //   { return doClone(old, newCapacity, false); };

   //static CRefCtBuf* realloc(CRefCtBuf* old, unsigned newCapacity)
   //   { return doClone(old, newCapacity, true); };

   static CRefCtBuf* update(CRefCtBuf* b, const char* s, // s NOT null-terminated
                            unsigned sz, unsigned beg=0) {
      CRefCtBuf* rv, *todel=nullptr; 
      b->lock();
      unsigned c = b->refCount();
      if (c > 1) {
         rv = doClone(b, beg+sz, beg);
         b->refCount(c-1);
         b->unlock();
      }
      else {
         // If refCount == 1, the updating thread has the only reference
         // to the object, so there is no need to lock any more.
         b->unlock();
         if (b->capacity() < beg+sz) {
            rv = doClone(b, beg+sz, beg);
            todel = b;
         }
         else rv = b;
      }

      memmove(rv->data(beg), s, sz);
      rv->size(beg+sz);

      if (todel != nullptr)
         delete [] todel;
      return rv;
   }

   static CRefCtBuf* concat(CRefCtBuf& b1, const CRefCtBuf& b2) {
      return update(&b1, b2.data(), b2.size(), b1.size());
   }

   static CRefCtBuf *concat(CRefCtBuf& b1, const char* s, unsigned sz) {
      return update(&b1, s, sz, b1.size());
   }

 private:
   static CRefCtBuf* 
   doClone(CRefCtBuf* old, unsigned newCapacity, int cpbytes=-1) {
      if (old == nullptr) return nullptr;
      CRefCtBuf* rv = alloc(newCapacity? newCapacity : old->capacity());
      if (rv != nullptr) {
         rv->refCount(1);
         if (cpbytes == -1)
            cpbytes = old->size();
         memcpy((void*)rv->data(), (void*)old->data(), cpbytes);
         rv->size(cpbytes);
      }
      return rv;
   };
};

// @@@@ Data encoding in CStringImpl currently works only for Little Endian :-(
#define MSBYTE 7
#define NMSBYTE 6

//
// Compact string representation that can store short string (length <= sz)
// directly, while using CRefCtBuf to implement longer strings. 
//
// Additional options such as (a) storing a reference to an already allocated
// char* buffer, and (b) de-duplication using a hash table of strings are not
// included. For (a), most likely use cases involve string constants and strings
// read from input. String constants are very few in number, and it is not worth
// saving the storage. Strings read from input are likely read into very large
// intermediate buffers first, since the size of input strings cannot be
// predicted in advance. These have to be copied out of that buffer any way. For
// (b), we can implement de-dup'd strings in a subclass. That would allow you to
// have both types of strings, and avoid hashtable overhead in those cases where
// de-dup'ing isn't expected to save much. (In addition, note that being
// de-dep'd is not an intrinsic property of a string. So, if you called normal
// string operations on a de-dup'd string, it would be fine. We can say the same
// when the roles are reversed as well.)
//

template <unsigned sz>
class CStringImpl {
   static_assert(((sz >= 8) && (sz <= 120) && ((sz&0x7) == 0)), "Class CStringImpl: invalid size parameter");

 private:
   union {
      unsigned long rep_; // stores CRefCtBuf* with MSByte 8 on Little Endian
      unsigned char ch[sz]; 
      // ch[0] = 080 if the object contains a pointer to CRefCtBuf object
      //       = 0x80|(len+2) if the string is locally stored
      //       = first char of sz-length string if first char is < 0x80
   };

   bool isPtr() const { return (ch[sz-1] == 0x80); };

   void ptr(CRefCtBuf* p, bool manipulateRefCounts=true) { 
      if (manipulateRefCounts) {
         deletePtr();
         if (!p->incRefCount()) // at max refcount, so can't share. Make a copy
            p = CRefCtBuf::alloc(((const CRefCtBuf*)p)->data(), p->size());
      }
      rep_ = (unsigned long)p;  
      ch[sz-1] = 0x80; 
   };

   CRefCtBuf* ptr() { return (CRefCtBuf*) (((long)(rep_ << 8)) >> 8); };

   const CRefCtBuf* ptr() const 
      { return const_cast<CStringImpl<sz>*>(this)->ptr(); };

   void size(unsigned siz) {
      ch[sz-1] = (0x80 | (siz+2));
   };

   void doCopy(const char* s, unsigned len) {
      if ((len > sz) || (len == sz && (s[sz-1] & 0x80)))
         if (isPtr())
            ptr(CRefCtBuf::update(ptr(), s, len), false);
         else ptr(CRefCtBuf::alloc(s, len), false);
      else {
         deletePtr();
         size(len);
         memcpy(&ch[0], s, len);
      }
   };

   void deletePtr() {
      if (isPtr()) 
         if (ptr()->decRefCount() == 0)
            delete [] ptr();
   };

 public:
   CStringImpl() { 
      size(0); // non-pointer, zero-length string.
   };

   CStringImpl(const char* s, unsigned len) {
      size(0);
      doCopy(s, len);
   };

   CStringImpl(const CStringImpl<sz>& s) {
      size(0); // default initialization as non-pointer
      *this = s;
   };

   CStringImpl(const CStringImpl<sz>& s1, const CStringImpl<sz>& s2) {
      size(0);
      *this = s1;
      *this += s2;
   };

   ~CStringImpl() {
      deletePtr();
   };

   unsigned size() const {
      if (isPtr())
         return ptr()->size();
      else if (ch[sz-1] & 0x80) 
         return (ch[sz-1] & 0x7f)-2;
      else return sz;
   }

   const char* data(unsigned i=0) const {
      //assert(i <= size());
      if (isPtr()) 
         return ptr()->data(i);
      else return (const char*)&ch[i];
   }

   const CStringImpl<sz>& operator=(const CStringImpl<sz>& s) {
      if (this != &s) {
         if (s.isPtr())
            ptr(const_cast<CRefCtBuf*>(s.ptr()));
         else doCopy(s.data(), s.size());
      }
      return *this;
   };

   void operator+=(const CStringImpl<sz> &s) {
      if (isPtr())
         ptr(CRefCtBuf::concat(*ptr(), s.data(), s.size()), false);
      else {
         unsigned lens = s.size();
         if (lens != 0) {
            unsigned len = size();
            if (len == 0)
               *this = s;
            else {
               unsigned nlen = len + lens;
               if (nlen > sz || (nlen == sz && (*s.data(lens-1) & 0x80))) {
                  CRefCtBuf* s1 = CRefCtBuf::alloc(data(), len, nlen);
                  ptr(CRefCtBuf::concat(*s1, s.data(), lens), false);
               }
               else {
                  size(nlen);
                  memmove(const_cast<char*>(data(len)), s.data(), lens);
               }
            }
         }
      }
   }
};

#define CString CStringImpl<8>

static_assert((sizeof(CStringImpl<8>)==8), "Class CStringImpl: invalid size");
template <unsigned sz>
ostream& operator<<(ostream&os, const CStringImpl<sz>& s) 
     { os.write(s.data(), s.size()); return os; };
#endif
