%if 0%{?fedora} || 0%{?rhel} >= 8
%bcond_with python2
%bcond_without python3
%else
%bcond_without python2
%bcond_with python3
%endif

# Without this, the resulting insertlib will segfault
%define _lto_cflags %{nil}

%define debug_package %{nil}

%global pkgname rpm-head-signing
%global srcname rpm_head_signing

Name:           python-rpm-head-signing
Version:        1.5
Release:        1%{?dist}
Summary:        Small python module to extract RPM header and file digests
License:        MIT
URL:            https://github.com/fedora-iot/rpm-head-signing
Source0:        https://github.com/fedora-iot/rpm-head-signing/archive/refs/tags/v%{version}.tar.gz

%if %{with python3}
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-koji
BuildRequires:  python%{python3_pkgversion}-rpm
BuildRequires:  python%{python3_pkgversion}-cryptography
BuildRequires:  python%{python3_pkgversion}-pyxattr
%endif
%if %{with python2}
BuildRequires:  python2-devel
BuildRequires:  python2-setuptools
BuildRequires:  python2-koji
BuildRequires:  python2-cryptography
BuildRequires:  pyxattr
%endif
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  ima-evm-utils
BuildRequires:  ima-evm-utils-devel
BuildRequires:  rpm-devel
BuildRequires:  rpm-sign
BuildRequires:  cpio
BuildRequires:  valgrind
BuildRequires:  zstd

%{?python_enable_dependency_generator}

%description
Python tools for signing RPMs without sending over the full RPM.


%if %{with python2}
%package -n python2-%{pkgname}
Summary:        %{summary}
%{?python_provide:%python_provide python2-%{pkgname}}

%if %{undefined python_enable_dependency_generator} && %{undefined python_disable_dependency_generator}
# Put manual requires here:
Requires:       python2-koji
Requires:       python2-six
%if 0%{?fedora} || 0%{?rhel} >= 8
Requires:       python2-pyxattr
Requires:       rpm-python
%else
Requires:       pyxattr
Requires:       rpm-python
%endif
%endif

%description -n python2-%{pkgname}
Python tools for signing RPMs without sending over the full RPM.
%endif


%if %{with python3}
%package -n python%{python3_pkgversion}-%{pkgname}
Summary:        %{summary}
%{?python_provide:%python_provide python3-%{pkgname}}

%if %{undefined python_enable_dependency_generator} && %{undefined python_disable_dependency_generator}
# Put manual requires here:
Requires:       python%{python3_pkgversion}-koji
Requires:       python%{python3_pkgversion}-six
Requires:       python%{python3_pkgversion}-xattr
Requires:       python%{python3_pkgversion}-rpm
%endif

%description -n python%{python3_pkgversion}-%{pkgname}
Python tools for signing RPMs without sending over the full RPM.
%endif


%prep
%autosetup -p1 -n rpm-head-signing-%{version}
for lib in rpm_head_signing/*.py; do
 sed '1{\@^#!/usr/bin/env python@d}' $lib > $lib.new
 mv $lib.new $lib
done


%build
%if %{with python2}
%py2_build
%endif

%if %{with python3}
%py3_build
%endif


%install
%if %{with python2}
%py2_install
%endif

%if %{with python3}
%py3_install
%endif


%check
# To make sure we get to use the installed version
mv rpm_head_signing rpm_head_signing.orig

%if %{with python2}
PYTHONPATH=%{buildroot}%{python2_sitearch} SKIP_BYTEORDER_CHECK=true SKIP_IMA_LIVE_CHECK=true ONLY_ALTERNATIVE_EVMCTL_CHECK=true python2 test.py
%endif
%if %{with python3}
PYTHONPATH=%{buildroot}%{python3_sitearch} SKIP_IMA_LIVE_CHECK=true python3 test.py
%endif


%if %{with python2}
%files -n  python2-%{pkgname}
%license LICENSE
%{python2_sitearch}/%{srcname}/
%{python2_sitearch}/%{srcname}-%{version}-py%{python2_version}.egg-info/
%{_bindir}/verify-rpm-ima-signatures
%endif

%if %{with python3}
%files -n  python%{python3_pkgversion}-%{pkgname}
%license LICENSE
%{python3_sitearch}/%{srcname}/
%{python3_sitearch}/%{srcname}-%{version}-py%{python3_version}.egg-info/
%{_bindir}/verify-rpm-ima-signatures
%endif


%changelog
* Wed Sep 29 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.5-1
- feat: add determine function to determine package status

* Mon Sep 27 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.4.3-1
- Fix: ignore RPM Ghost files
- Fix: ignore empty RPMs

* Tue Sep 14 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.4.2-1
- Ignore symbolic links when verifying RPMs

* Fri Sep 10 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.4.1-1
- Ensure xattrs are passed in as bytes

* Mon Aug 23 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.4-1
- Add verify-rpm-ima-signatures script to verify RPM signatures

* Mon Aug 16 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.3-1
- Feature: fix byte order on insert_signatures
- Fix: Compile on F32
- Fix: Beta RPM version parsing

* Thu Aug 05 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.2-1
- Generate zero digest

* Wed Aug 04 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.1-1
- Fix a segfault in case of an early error
- Update spec file to support python2
- Support IMA injection only

* Wed Jun 30 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.0-1
- Bump version to v1

* Wed Apr 28 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-2
- Moved ima_lookup.so to libdir

* Mon Apr 26 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-1
- Initial packaging
