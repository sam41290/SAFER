/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef USER_H
#define USER_H

#include "default.h"
#include "utility.h"

/* BaseLH     */
/* BaseStride */
/* Taint      */

namespace SBA {
   /* -------------------------------- AbsVal ------------------------------- */
   #define ABSVAL_INIT(abs_domain)                                             \
      abs_domain(t==T::TOP? abs_domain::T::TOP:                                \
                (t==T::BOT? abs_domain::T::BOT: abs_domain::T::PC))
   #define ABSVAL_INIT_EMPTY(abs_domain)                                       \
      abs_domain(abs_domain::T::EMPTY)
   #define ABSVAL_UNARY(abs_op)                                                \
      void abs_op() {                                                          \
         std::get<0>(value).abs_op();                                          \
         std::get<1>(value).abs_op();                                          \
         std::get<2>(value).abs_op();                                          \
      }
   #define ABSVAL_BINARY(abs_op)                                               \
      void abs_op(const AbsVal& obj) {                                         \
         std::get<0>(value).abs_op(std::get<0>(obj.value));                    \
         std::get<1>(value).abs_op(std::get<1>(obj.value));                    \
         std::get<2>(value).abs_op(std::get<2>(obj.value));                    \
      }
   #define ABSVAL_BOOL(abs_op)                                                 \
      bool abs_op() const {                                                    \
         return std::get<0>(value).abs_op() &&                                 \
                std::get<1>(value).abs_op() &&                                 \
                std::get<2>(value).abs_op();                                   \
      }
   #define ABSVAL_PARAM(abs_op, param_t, param)                                \
      void abs_op(param_t param) {                                             \
         std::get<0>(value).abs_op(param);                                     \
         std::get<1>(value).abs_op(param);                                     \
         std::get<2>(value).abs_op(param);                                     \
      }
   #define ABSVAL_STRING()                                                     \
              string("      ").append(std::get<0>(value).to_string())          \
      .append(string("\n      ")).append(std::get<1>(value).to_string())       \
      .append(string("\n      ")).append(std::get<2>(value).to_string())
   #define ABSVAL_TYPE(abs_type) {                                             \
         std::get<0>(value).type(BaseLH::T::abs_type);                         \
         std::get<1>(value).type(BaseStride::T::abs_type);                     \
         std::get<2>(value).type(Taint::T::abs_type);                          \
      }

   #define ABSVAL_CLASS                                                        \
      class AbsVal {                                                           \
       public:                                                                 \
         enum class T: uint8_t {TOP, BOT, PC};                                 \
         tuple<BaseLH,BaseStride,Taint> value;                                 \
                                                                               \
       public:                                                                 \
         AbsVal(): value(make_tuple(ABSVAL_INIT_EMPTY(BaseLH),                 \
                                    ABSVAL_INIT_EMPTY(BaseStride),             \
                                    ABSVAL_INIT_EMPTY(Taint))) {};             \
         AbsVal(T t): value(make_tuple(ABSVAL_INIT(BaseLH),                    \
                                       ABSVAL_INIT(BaseStride),                \
                                       ABSVAL_INIT(Taint))) {};                \
         AbsVal(const BaseLH& a, const BaseStride& b, const Taint& c):         \
                value(make_tuple(a,b,c)) {};                                   \
                                                                               \
       public:                                                                 \
         ABSVAL_BINARY(abs_union);                                             \
         ABSVAL_BINARY(add);                                                   \
         ABSVAL_BINARY(sub);                                                   \
         ABSVAL_BINARY(mul);                                                   \
         ABSVAL_BINARY(div);                                                   \
         ABSVAL_BINARY(mod);                                                   \
         ABSVAL_BINARY(lshift);                                                \
         ABSVAL_UNARY(abs);                                                    \
         ABSVAL_UNARY(neg);                                                    \
         ABSVAL_BOOL(top);                                                     \
         ABSVAL_BOOL(bot);                                                     \
         ABSVAL_BOOL(empty);                                                   \
         ABSVAL_BOOL(pc);                                                      \
         ABSVAL_PARAM(mode, uint8_t, b);                                       \
         string to_string() const {return ABSVAL_STRING();};                   \
         void clear() {ABSVAL_TYPE(EMPTY);};                                   \
         void fill(T type) {                                                   \
            if (type == T::TOP) {ABSVAL_TYPE(TOP);}                            \
            else {ABSVAL_TYPE(BOT);}                                           \
         };                                                                    \
      };
   /* ---------------------------- EXECUTE & EVAL --------------------------- */
   #define EXECUTE_ASSIGN(state)                                               \
           auto destination = dst()->simplify();                               \
           auto source = src()->simplify();                                    \
           auto size_d = destination->mode_size();                             \
           auto size_s = source->mode_size();                                  \
                                                                               \
           /* dst is register */                                               \
           IF_RTL_TYPE(Reg, destination, reg, {                                \
              auto aval_s = source->eval(state);                               \
              aval_s.mode(size_d);                                             \
              if (reg->reg() == ARCH::stack_ptr)                               \
                 CHECK_UNINIT(state, aval_s, size_d, 0x4);                     \
              state.update(get_id(reg->reg()), aval_s);                        \
           }, {                                                                \
           /* dst is memory */                                                 \
           IF_RTL_TYPE(Mem, destination, mem, {                                \
              auto aval_addr = mem->addr()->eval(state);                       \
              auto init_size = mem->addr()->mode_size();                       \
              CHECK_UNINIT(state, aval_addr, init_size, 0x1);                  \
              if (ABSVAL(BaseLH,aval_addr).top()) {                            \
                 state.clobber(REGION::STACK);                                 \
                 state.clobber(REGION::STATIC);                                \
              }                                                                \
              else if (ABSVAL(BaseLH,aval_addr).notlocal())                    \
                 state.clobber(REGION::STATIC);                                \
              else {                                                           \
                 IF_MEMORY_ADDR(aval_addr, r, range, {                         \
                    auto aval_s = source->eval(state);                         \
                    aval_s.mode(size_d);                                       \
                    if (r == REGION::STACK && range == Range::ZERO)            \
                       CHECK_UNINIT(state, aval_s, size_d, 0x4);               \
                    auto const& l = get_id(r, range.lo());                     \
                    auto const& h = get_id(r, range.hi());                     \
                    state.update(l, h, size_d, aval_s);                        \
                 });                                                           \
              }                                                                \
           }, {                                                                \
           /* dst is pc */                                                     \
           IF_RTL_TYPE(NoType, destination, no_type, {                         \
              if (no_type->to_string().compare("pc") == 0) {                   \
                 /* check for uninitialised cf target */                       \
                 auto aval_s = source->eval(state);                            \
                 aval_s.mode(size_d);                                          \
                 CHECK_UNINIT(state, aval_s, size_s, 0x2);                     \
                 /* handle indirect jumps */                                   \
                 if (state.loc.insn->indirect_target() != nullptr) {           \
                    /* update jump tables */                                   \
                    state.loc.func->target_expr[state.loc.insn->offset()]      \
                                     = ABSVAL(BaseStride,aval_s).clone();      \
                    LOG3("update(pc):\n" << aval_s.to_string());               \
                    /* replace cf target with T::PC */                         \
                    IF_RTL_TYPE(Reg, source, reg, {                            \
                       state.update(get_id(reg->reg()),AbsVal(AbsVal::T::PC)); \
                    }, {                                                       \
                    IF_RTL_TYPE(Mem, source, mem, {                            \
                       auto aval_addr = mem->addr()->eval(state);              \
                       auto init_size = mem->addr()->mode_size();              \
                       CHECK_UNINIT(state, aval_addr, init_size, 0x1);         \
                       IF_MEMORY_ADDR(aval_addr, r, range, {                   \
                          auto const& l = get_id(r, range.lo());               \
                          auto const& h = get_id(r, range.hi());               \
                          state.update(l, h, 8, AbsVal(AbsVal::T::PC));        \
                       });                                                     \
                    }, {});                                                    \
                    });                                                        \
                 }                                                             \
                 /* handle conditional jumps */                                \
              }                                                                \
           }, {});                                                             \
           });                                                                 \
           });
   #define EVAL_CONST(state)                                                   \
           return AbsVal(BaseLH(Range(i_,i_)),                                 \
                  BaseStride(BaseStride::Base(i_)),                            \
                  Taint(0x0,nullptr));
   #define EVAL_REGISTER(state)                                                \
           AbsVal res;                                                         \
           if (r_ == ARCH::insn_ptr) {                                         \
              auto pc = state.loc.insn->next_offset();                         \
              res = AbsVal(BaseLH(staticSym, Range(pc,pc)),                    \
                           BaseStride(BaseStride::Base(pc)),                   \
                           Taint(0x0, nullptr));                               \
           }                                                                   \
           else                                                                \
              res = state.value(get_id(r_));                                   \
           res.mode(mode_size());                                              \
           return res;
   #define EVAL_MEMORY(state)                                                  \
           AbsVal res(AbsVal::T::TOP);                                         \
           auto aval_addr = addr()->eval(state);                               \
           auto size = mode_size();                                            \
           CHECK_UNINIT(state, aval_addr, size, 0x1);                          \
           IF_MEMORY_ADDR(aval_addr, r, range, {                               \
              auto const& lo = get_id(r, range.lo());                          \
              auto const& hi = get_id(r, range.hi());                          \
              auto stride = mode_size();                                       \
              res = state.value(lo, hi, stride);                               \
              res.mode(stride);                                                \
           });                                                                 \
           ABSVAL(BaseStride,res).mem(ABSVAL(BaseStride,aval_addr),size);      \
           return res;
   #define EVAL_NOTYPE(state)                                                  \
           AbsVal res(AbsVal::T::TOP);                                         \
           if (s_.compare("pc") == 0) {                                        \
              auto pc = state.loc.insn->next_offset();                         \
              Range range(pc,pc);                                              \
              res = AbsVal(BaseLH(staticSym, Range(pc,pc)),                    \
                           BaseStride(BaseStride::Base(pc)),                   \
                           Taint(0x0, nullptr));                               \
           }                                                                   \
           return res;
   #define EXECUTE_CALL(state)     DEFAULT_EXECUTE_CALL(state)
   #define EXECUTE_EXIT(state)     DEFAULT_EXECUTE_EXIT(state)
   #define EVAL_SUBREG(state)      DEFAULT_EVAL_SUBREG(state)
   #define EVAL_IFELSE(state)      DEFAULT_EVAL_IFELSE(state)
   #define EVAL_CONVERSION(state)  DEFAULT_EVAL_CONVERSION(state)
   #define EVAL_UNARY(state)       DEFAULT_EVAL_UNARY(state)
   #define EVAL_BINARY(state)      DEFAULT_EVAL_BINARY(state)
   #define EVAL_COMPARE(state)     DEFAULT_EVAL_COMPARE(state)
}

#endif
