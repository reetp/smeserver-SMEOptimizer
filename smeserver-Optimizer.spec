%define name smeserver-Optimizer
%define version 0.1
%define release 01
Summary: Plugin to enable enhanced mail scanning
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
License: GNU GPL version 2
URL: http://libreswan.org/
Group: SMEserver/addon
Source: %{name}-%{version}.tar.gz

BuildRoot: /var/tmp/%{name}-%{version}
BuildArchitectures: noarch
BuildRequires: e-smith-devtools
Requires:  e-smith-release >= 9.0
Requires:  perl-Digest-MD5-File => 0.07
Requires:  perl-JSON >= 2.5
AutoReqProv: no

%description
smeserver-Optimizer adds further mail checks for Koozali SME Server

%changelog
* Wed Jun 07 2017 John Crisp <jcrisp@safeandsoundit.co.uk> 0.1-1
- initial release

%prep
%setup

%build
perl createlinks

%install
rm -rf $RPM_BUILD_ROOT
(cd root ; find . -depth -print | cpio -dump $RPM_BUILD_ROOT)
rm -f %{name}-%{version}-filelist
/sbin/e-smith/genfilelist $RPM_BUILD_ROOT > %{name}-%{version}-filelist
echo "%doc COPYING" >> %{name}-%{version}-filelist


%clean
cd ..
rm -rf %{name}-%{version}

%files -f %{name}-%{version}-filelist
%defattr(-,root,root)

%pre
%preun

%post
/sbin/e-smith/expand-template /etc/crontab
/sbin/e-smith/expand-template /var/service/qpsmtpd/config/peers/0
sv t spamd
sv t qpsmtpd

%postun
/sbin/e-smith/expand-template /etc/crontab
/sbin/e-smith/expand-template /var/service/qpsmtpd/config/peers/0
rm /etc/mail/spamassassin/smeoptimizer.cf
rm /usr/share/qpsmtpd/plugins/smeoptimizer
sv t spamd
sv t qpsmtpd