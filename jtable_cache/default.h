/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef DEFAULT_H
#define DEFAULT_H

/* -------------------------------------------------------------------------- */
#define ABSVAL(abs_domain, aval)                                               \
   std::get<abs_domain::ID>(aval.value)


#define IF_MEMORY_ADDR(addr, region, range, CODE)                              \
   if (ABSVAL(BaseLH,addr).concrete()) {                                       \
      auto sym = ABSVAL(BaseLH,addr).base();                                   \
      if (sym == stackSym) {                                                   \
         auto region = REGION::STACK;                                          \
         auto range = ABSVAL(BaseLH,addr).range();                             \
         CODE                                                                  \
      }                                                                        \
      else if (sym == staticSym || sym == 0) {                                 \
         auto region = REGION::STATIC;                                         \
         auto range = ABSVAL(BaseLH,addr).range();                             \
         CODE                                                                  \
      }                                                                        \
   }


#define CHECK_UNINIT(state, aval, init_size, error)                            \
   if (!ABSVAL(Taint,aval).valid(init_size)) {                                 \
      state.loc.func->uninit |= error;                                         \
      LOG3((error == 0x1? "uninit memory address":                             \
           (error == 0x2? "uninit control target":                             \
           (error == 0x4? "uninit critical data": ""))));                      \
   }
/* -------------------------------------------------------------------------- */
#define DEFAULT_EXECUTE_CALL(state)                                            \
   if (state.config.enable_callee_effect)                                      \
      for (auto r: ARCH::return_value)                                         \
         state.clobber(get_id(r));


#define DEFAULT_EXECUTE_EXIT(state)
/* -------------------------------------------------------------------------- */
#define DEFAULT_EVAL_SUBREG(state)                                             \
   AbsVal res = expr_->eval(state);                                            \
   if (bytenum() == 0)                                                         \
      res.mode(mode_size());                                                   \
   else                                                                        \
      res.fill(AbsVal::T::TOP);                                                \
   return res;


#define DEFAULT_EVAL_IFELSE(state)                                             \
   AbsVal res = if_expr()->eval(state);                                        \
   AbsVal else_val = else_expr()->eval(state);                                 \
   res.abs_union(else_val);                                                    \
   return res;


#define DEFAULT_EVAL_CONVERSION(state)                                         \
   auto expr = simplify();                                                     \
   AbsVal res = expr->eval(state);                                             \
   res.mode(mode_size());                                                      \
   return res;


#define DEFAULT_EVAL_UNARY(state)                                              \
   AbsVal res(AbsVal::T::TOP);                                                 \
   switch (op_) {                                                              \
      case OP::NEG: {                                                          \
         res = operand_->eval(state);                                          \
         res.neg();                                                            \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      case OP::ABS: {                                                          \
         res = operand_->eval(state);                                          \
         res.abs();                                                            \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      default:                                                                 \
         break;                                                                \
   }                                                                           \
   return res;


#define DEFAULT_EVAL_BINARY(state)                                             \
   AbsVal res(AbsVal::T::TOP);                                                 \
   switch (op_) {                                                              \
      case OP::PLUS: {                                                         \
         res = operand(0)->eval(state);                                        \
         auto op2 = operand(1)->eval(state);                                   \
         res.add(op2);                                                         \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      case OP::MINUS: {                                                        \
         res = operand(0)->eval(state);                                        \
         auto op2 = operand(1)->eval(state);                                   \
         res.sub(op2);                                                         \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      case OP::MULT: {                                                         \
         res = operand(0)->eval(state);                                        \
         auto op2 = operand(1)->eval(state);                                   \
         res.mul(op2);                                                         \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      case OP::ASHIFT: {                                                       \
         res = operand(0)->eval(state);                                        \
         auto op2 = operand(1)->eval(state);                                   \
         res.lshift(op2);                                                      \
         res.mode(mode_size());                                                \
         break;                                                                \
      }                                                                        \
      default: {                                                               \
         res.fill(AbsVal::T::TOP);                                             \
         break;                                                                \
      }                                                                        \
   }                                                                           \
   return res;


#define DEFAULT_EVAL_COMPARE(states)                                           \
   return AbsVal(AbsVal::T::TOP);                                              \

#endif
