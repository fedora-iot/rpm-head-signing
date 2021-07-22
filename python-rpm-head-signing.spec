%if 0%{?fedora} || 0%{?rhel} >= 8
%bcond_with python2
%bcond_without python3
%else
%bcond_without python2
%bcond_with python3
%endif

%define debug_package %{nil}

%global pkgname rpm-head-signing
%global srcname rpm_head_signing

Name:           python-rpm-head-signing
Version:        1.0
Release:        1%{?dist}
Summary:        Small python module to extract RPM header and file digests
License:        MIT
URL:            https://github.com/fedora-iot/rpm-head-signing
Source0:        https://github.com/fedora-iot/rpm-head-signing/archive/refs/tags/v%{version}.tar.gz

%if %{with python3}
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
%endif
%if %{with python2}
BuildRequires:	python2-devel
BuildRequires:	python2-setuptools
%endif
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  ima-evm-utils-devel
BuildRequires:	rpm-devel

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


%build
%if %{with python2}
%py2_build
%endif

%if %{with python3}
%py3_build
%endif


%install
rm -rf $RPM_BUILD_ROOT

%if %{with python2}
%py2_install
%endif

%if %{with python3}
%py3_install
%endif


%check


%if %{with python2}
%files -n  python2-%{pkgname}
%license LICENSE
%{python2_sitearch}/%{srcname}/
%{python2_sitearch}/%{srcname}-%{version}-py%{python2_version}.egg-info/
%endif

%if %{with python3}
%files -n  python%{python3_pkgversion}-%{pkgname}
%license LICENSE
%{python3_sitearch}/%{srcname}/
%{python3_sitearch}/%{srcname}-%{version}-py%{python3_version}.egg-info/
%endif


%changelog
* Wed Jun 30 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.0-1
- Bump version to v1

* Wed Apr 28 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-2
- Moved ima_lookup.so to libdir

* Mon Apr 26 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-1
- Initial packaging
