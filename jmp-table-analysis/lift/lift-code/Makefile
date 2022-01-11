
# FwdMap is a learning based system which automatically builds assembly to IR
# translators using code generators of modern compilers.

# Copyright (C) 2014 - 2015 by Niranjan Hasabnis and R.Sekar in Secure Systems
# Lab, Stony Brook University, Stony Brook, NY 11794.

# This program is free software; you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation; either version 2 of the License, or 
# (at your option) any later version. 

# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# GNU General Public License for more details. 

# You should have received a copy of the GNU General Public License 
# along with this program; if not, write to the Free Software 
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.

#CC=gcc-7.3

ARCH=X64
# ARCH=ARM
# ARCH=AVR

export OCAMLRUNPARAM=b
TESTS := $(wildcard *.imap)
TESTDOT := $(TESTS:%.imap=%.dot)
TESTPDF := $(TESTS:%.imap=%.pdf)

CAMLC := ocamlc -g -pp "camlp4o pa_macro.cmo -DARCH_${ARCH}"
CAMLOPTC := ocamlopt $(PROFILE) -g -pp "camlp4o pa_macro.cmo -DARCH_${ARCH}"
CAMLFIND := ocamlfind

ARCH_PARSER=parse${ARCH}

%.cmo: %.ml
	$(CAMLC) -c -g $<

%.cmx: %.ml
	$(CAMLOPTC) -c -g $<

%.cmi: %.mli
	$(CAMLC) -c -g $<

%.ml: %.mll
	ocamllex $<

%.ml: %.mly
	ocamlyacc $<

%.mli: %.mly %.ml
	ocamlyacc $<

learnopt: learn.cmi ${ARCH_PARSER}.cmi lexAsm.cmx ${ARCH_PARSER}.cmx parseRtl.cmi lexRtl.cmx parseRtl.cmx learn.cmx main.cmx
	$(CAMLOPTC) -g -o $@ str.cmxa lexAsm.cmx ${ARCH_PARSER}.cmx lexRtl.cmx parseRtl.cmx learn.cmx main.cmx

learn: learn.cmi ${ARCH_PARSER}.cmi lexAsm.cmo ${ARCH_PARSER}.cmo parseRtl.cmi lexRtl.cmo parseRtl.cmo learn.cmo main.cmo
	$(CAMLC) -g -o $@ str.cma lexAsm.cmo ${ARCH_PARSER}.cmo lexRtl.cmo parseRtl.cmo learn.cmo main.cmo

main.cmx: main.ml learn.ml learn.mli

interface: learn.cmi ${ARCH_PARSER}.cmi lexAsm.cmx ${ARCH_PARSER}.cmx parseRtl.cmi lexRtl.cmx parseRtl.cmx learn.cmx
	$(CAMLOPTC) -output-obj -o ocaml_interface.o str.cmxa lexAsm.cmx ${ARCH_PARSER}.cmx lexRtl.cmx parseRtl.cmx learn.cmx main.ml

all: interface learnopt

64test/%.dot: 64test/%.imap all
	./learnopt -tr $< -dotf $(<:%.imap=%.dot)

%.pdf: 64test/%.dot
	dot -Tpdf -Nshape=box $< > $(<:%.dot=%.pdf)
	xpdf $(<:%.dot=%.pdf)

.PHONY: check
check:
	for testf in `ls 64test/test*.imap`; \
	do \
		echo -n "Checking $${testf} ..."; \
		outf=`mktemp -p /tmp` ; \
		./learnopt -tr $${testf} > $${outf} 2>&1; \
		fs=`grep "FAIL" -w $${outf} | cut -d ':' -f 2` ; \
		if [ "$${fs}" -eq "0" ]; \
		then	 \
			echo "Pass"; \
		else \
			echo "Fail"; \
		fi  \
	done; \

alldot: $(TESTDOT)

allpdf: $(TESTPDF)

clean:
	rm -f *.o *.cmi *.cmo *.cmx *.a *.so *.cma *.cmxa parseRtl.mli parseRtl.ml parseSymRtl.mli parseSymRtl.ml lexRtl.mli lexRtl.ml parseAsm.ml lexAsm.mli lexAsm.ml
	rm -f parseX64.mli parseARM.mli parseAVR.mli learnopt learn
	rm -f -r 64test/output
