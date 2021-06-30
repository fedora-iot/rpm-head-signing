%{?!python3_pkgversion:%global python3_pkgversion 3}

%define debug_package %{nil}

%global srcname rpm_head_signing

Name:           python-rpm_head_signing
Version:        1.0
Release:        1%{?dist}
Summary:        Small python module to extract RPM header and file digests
License:        MIT
URL:            https://github.com/fedora-iot/rpm-head-signing
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  ima-evm-utils-devel

%{?python_enable_dependency_generator}

%description
Python tools for signing RPMs without sending over the full RPM.


%package -n python%{python3_pkgversion}-%{srcname}
Summary:        %{summary}
%{?python_provide:%python_provide python3-%{srcname}}

%if %{undefined python_enable_dependency_generator} && %{undefined python_disable_dependency_generator}
# Put manual requires here:
Requires:       python%{python3_pkgversion}-koji
Requires:       python%{python3_pkgversion}-six
Requires:       python%{python3_pkgversion}-xattr
Requires:       python%{python3_pkgversion}-rpm
%endif

%description -n python%{python3_pkgversion}-%{srcname}
Python tools for signing RPMs without sending over the full RPM.


%package -n rpm_head_signing-tools
Summary:        Small tool

%description -n rpm_head_signing-tools
Small tools useful for RPM Head signing

%prep
%autosetup -p1 -n %{name}-%{version}


%build
%py3_build
make binaries


%install
rm -rf $RPM_BUILD_ROOT
%py3_install
mkdir -p %{buildroot}%{_bindir}/
install ima_calc_keyid %{buildroot}%{_bindir}/
mkdir -p %{buildroot}%{_libdir}/


%check


%files -n  python%{python3_pkgversion}-%{srcname}
%license LICENSE
%{python3_sitearch}/%{srcname}/
%{python3_sitearch}/%{srcname}-%{version}-py%{python3_version}.egg-info/

%files -n rpm_head_signing-tools
%{_bindir}/ima_calc_keyid


%changelog
* Web Jun 30 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 1.0-1
- Bump version to v1

* Wed Apr 28 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-2
- Moved ima_lookup.so to libdir

* Mon Apr 26 2021 Patrick Uiterwijk <patrick@puiterwijk.org> - 0.1-1
- Initial packaging
