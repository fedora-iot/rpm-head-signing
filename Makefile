SPEC_FILE	= python-rpm-head-signing.spec
NAME		= $(shell rpm -q --specfile $(SPEC_FILE) --qf "%{name}\n" | head -1 )
VERSION		= $(shell rpm -q --specfile $(SPEC_FILE) --qf "%{version}\n" | head -1)
RELEASE		= $(shell rpm -q --specfile $(SPEC_FILE) --qf "%{release}\n" | head -1)
NV		= $(NAME)-$(VERSION)
RPM_FLAGS	=	--define "_topdir	%(pwd)" \
			--define "_builddir	%{_topdir}" \
			--define "_rpmdir	%{_topdir}" \
			--define "_srcrpmdir	%{_topdir}" \
			--define '_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
			--define "_specdir	%{_topdir}" \
                        --define "_binary_filedigest_algorithm 1" \
                        --define "_source_filedigest_algorithm 1" \
                        --define "_binary_payload w9.gzdio" \
                        --define "_source_payload w9.gzdio" \
			--define "_sourcedir	%{_topdir}"

DATADIR		= $(shell rpm --eval "%{_datadir}")
TOPDIR		= $(shell echo `pwd`)

tar:
	mkdir -p $(NV)
	cp -rv Makefile ima_calc_keyid.c LICENSE Makefile README.md rpm_head_signing setup.py $(NV)/
	tar zcvf $(NV).tar.gz $(NV)
	rm -rf $(NV)

rpm:	tar
	rpmbuild $(RPM_FLAGS) -ba $(SPEC_FILE)

srpm:	tar
	rpmbuild $(RPM_FLAGS) -bs $(SPEC_FILE)

.PHONY: binaries
binaries: ima_calc_keyid

ima_calc_keyid:
	gcc -Wall -Werror -fpic ima_calc_keyid.c -o ima_calc_keyid -lcrypto -limaevm
