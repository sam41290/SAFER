#ifndef CVECTOR_H
#define CVECTOR_H

#include "Base.h"
#include <string.h>
#include <iostream>
#include <vector>
#include <initializer_list>

// @@@@ To fix: does not use ElemType copy constructor, does a bit-by-bit copy.
template<class ElemType> class CVector {
 private:
   unsigned frozen_: 1;
   unsigned siz_:18;
   unsigned long ptr_:45;

 public:
   unsigned max_size() const { return (1<<18)-1; };

   CVector(): frozen_(0), siz_(0), ptr_(0) {};
   CVector(const std::vector<ElemType>& v): frozen_(0), siz_(0), ptr_(0) {
      unsigned ns = v.size();
      assert_abort(ns <= max_size());
      for (unsigned i=0; i < ns; i++)
         push_back(v[i]);
   };
   CVector(const std::initializer_list<ElemType>& v):frozen_(0),siz_(0),ptr_(0) {
      unsigned ns = v.size();
      assert_abort(ns <= max_size());
      for (auto& i: v)
         push_back(i);
   };
   CVector(const CVector<ElemType>& oth): frozen_(0), siz_(0), ptr_(0) {
      resize(oth.capacity(), &oth);
   };

   bool operator==(const CVector<ElemType>& oth) const {
      if (size() != oth.size()) 
         return false;
      for (unsigned j=0; j < size(); j++)
         if ((*this)[j] != oth[j]) return false;
      return true;
   };

   const CVector& operator=(const CVector<ElemType>& oth) {
      clear();
      resize(oth.capacity(), &oth);
      return *this;
   }

   ~CVector() { clear(); };

   unsigned size() const { return siz_; };

   void serialize(std::ostream& os) const {
      os << size() << std::endl;
      os.write((char*)base(), sizeof(ElemType)*size());
      os << std::endl;
   }

   void deserialize(std::istream& is) { // @@@@ Note: does not free current store
      unsigned n; char t;
      is >> n; assert_abort(n < max_size());
      is.read(&t, 1);
      assert_try(t == '\n');
      siz_ = n;
      frozen_ = true;
      base((ElemType*)new char[siz_*sizeof(ElemType)]);
      is.read((char*)base(), siz_*sizeof(ElemType));
      is.ignore(1);
   }

 private:
   ElemType* base() const {
      // @@@@ Works only on x86_64
      unsigned long b = ptr_ << 3;
      if ((b >> 47) > 0)
         b |= 0xffff000000000000;
      return (ElemType*)b;
   }
   void base(ElemType* p) {
      // @@@@ Works only on x86_64
      unsigned long b = (unsigned long)p;
      ptr_ = ((b << 16) >> 19);
   }
   unsigned recommendedCapacity() const {
      if (siz_ == 0) return 0;
      unsigned n = 31 - __builtin_clz(siz_);
      return (1<<(n+1));
   }

 public:
   unsigned capacity() const { 
      return frozen_ ? siz_ : recommendedCapacity();
   };
   const ElemType& operator[](unsigned i) const
      { assert_fix(i<siz_, assert_abort(siz_>0); i=0); return base()[i];};
   ElemType& operator[](unsigned i)
      { assert_fix(i<siz_, assert_abort(siz_>0); i=0); return base()[i];};

   void insert(unsigned i, const ElemType& e) {
      if (i==siz_) push_back(e);
      else {
         ElemType t((*this)[siz_-1]);
         push_back(t);
         for (unsigned j=siz_-1; j > i; j--)
            (*this)[j] = (*this)[j-1];
         (*this)[i] = e;
      }
   }

   void clear() {
      if (siz_ > 0)
         delete [] base();
      frozen_=0; siz_=0; ptr_=0;
   }

 private:
   void resize(unsigned tosiz, const CVector<ElemType>* src = 0) {
      if (tosiz < siz_) return;
      if (frozen_) unfreeze();
      if (src == 0) src = this;
      ElemType* p = (ElemType*) new char[tosiz*sizeof(ElemType)];
      char *q = (char*)(src->base());
      memcpy((void *)p, q, src->siz_*sizeof(ElemType));
      base(p);
      siz_ = src->siz_;
      if (src == this) delete [] q;
   };

 public:
   //void resetWithoutFreeing() {
   //   frozen_=0; siz_=0; ptr_=0;
   //};

   //void freeCurrentAndShallowCopy(CVector<ElemType>& cv) {
   //   char *q = (char*)(base());
   //   delete [] q;
   //   frozen_ = cv.frozen_;
   //   siz_ = cv.siz_;
   //   ptr_ = cv.ptr_;
   //}      
      
   void freeze() {
      if (!frozen_) {
         bool makesSenseToFreeze = 
            (((capacity() - size())*sizeof(ElemType)) >= 16) &&
            (size() + (size()/6) < capacity());
         // Savings will be at least 16 bytes, and at least 1/7th
         if (makesSenseToFreeze) {
            resize(siz_);
            frozen_ = 1;
         }
      }
   };
   bool isFrozen() const { return frozen_; };
   void unfreeze() {
      if (frozen_) {
         frozen_ = 0;
         resize(recommendedCapacity());
      }
   };
   void push_back(const ElemType& elem) {
      if (frozen_) {
         std::cout << "**** CVector::push_back: DANGEROUS: operation discarded: object is frozen\n";
         return;
      }
      unsigned newsz = siz_+1;
      if (newsz >= capacity()) {
         newsz = 2*capacity();
         if (newsz == 0) newsz = 2;
         if (newsz > max_size()+1) {
           std::cout << "CVector::push_back: DANGEROUS: operation discarded: capacity exceeded max_size\n";
           return;
         }
         resize(newsz);
      }
      new (&base()[siz_]) ElemType(elem);
      siz_++;
   }

   /* Don't support delete, or else you can get into repeated resizes if
      you alternate push_back and pop_back when siz_ is a power of 2. 
      Note we can't avoid resizing on pop_back because capacity is inferred
      from siz_. 

      We can fix this by allocating one more bit to specify the factor between
      size and capacity. We can increase this factor when size falls below
      half the capacity, and resize only when it reaches quarter capacity.
      This would mean doubling when utilization=1, and halving when util=0.25.
   */

   ElemType pop_back_inefficient() {
      if (frozen_) unfreeze();
      assert_abort(siz_ > 0);
      ElemType rv = base()[siz_-1];
      base()[siz_-1].~ElemType();
      siz_--;
      return rv;
   }
};

template<class ET> std::ostream& operator<<(std::ostream& os, 
                                            const CVector<ET>& cv) {
   for (unsigned i=0; i < cv.size(); i++)
      os << cv[i] << ' ';
   //os << std::endl;
   return os;
}

#endif
