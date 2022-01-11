/*
    FwdMap is a learning based system which automatically builds assembly to IR
    translators using code generators of modern compilers.

    Copyright (C) 2014 - 2015 by Niranjan Hasabnis and R.Sekar in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.

    This program is free software; you can redistribute it and/or modify 
    it under the terms of the GNU General Public License as published by 
    the Free Software Foundation; either version 2 of the License, or 
    (at your option) any later version. 

    This program is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
    GNU General Public License for more details. 

    You should have received a copy of the GNU General Public License 
    along with this program; if not, write to the Free Software 
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*/


%{
  open Learn
%}

/* File parser.mly */
%token <nativeint> INT
%token <string> ID
        %token <nativeint> FLOAT
%token LPAREN RPAREN LBRACK RBRACK OR COMMA COLON DONE
%start rtlinsn             /* the entry point */
%type <Learn.term> arg expr rtlinsn
%type <Learn.term list> args optMode
%%

rtlinsn:
  expr DONE               { $1 }
| DONE                    { raise End_of_file }
;

/* Colon is used to provide mode info (which is like type info) for operations. 
   For most operations, mode seems mandatory (e.g., reg:SI) but for some, it 
   seems optional (e.g., mult, parallel). It seems advantageous to parse the 
   mode as an argument of the operation, but to ensure that its optional
   nature does not mess up the position of other arguments, we make mode the
   last argument of the operation.
*/

/* For the parallel operator, the order of components (presumably) does not
   matter. In this case, to ensure that equal RTL is recognized as equal, it
   is advantageous to keep parallel's arguments in a canonical form, e.g., by
   keeping them in a sorted order. OTOH, it is reasonable to think that gcc
   itself will keep parallel in a canonical form for similar reasons. Plus,
   gcc may have a particular order in this canonical form that is advantageous,
   as opposed to an arbitrary order that would result from sorting. So, for now,
   we will not sort, but if we run into errors, then we will.
*/

expr: 
  LPAREN ID optMode args RPAREN   {
      let l = (*if $2 = "parallel" then (List.sort compare $4) else*) $4
      in Learn.OP(SCONST($2), l @ $3)
  };

optMode:
  /* empty */ { [] }
| COLON ID    { [OP(SCONST("mode:" ^ $2),[])] }
;

args: 
  /* empty */ {[]}
| arg args    {$1::$2}
;

arg:
  expr  { $1 }
| INT   { Learn.OP(ICONST($1), []) }
| FLOAT { Learn.OP(ICONST($1), []) }
| ID    { Learn.OP(SCONST($1), []) }
| LBRACK args RBRACK { 
    Learn.OP(SCONST("LBRACK_RBRACK"), $2 )
  }

