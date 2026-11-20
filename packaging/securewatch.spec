Name:           securewatch
Version:        %{securewatch_version}
Release:        %{securewatch_release}
Summary:        Local Linux security audit and reporting tool
License:        MIT
BuildArch:      noarch
Requires:       bash, coreutils, curl, gawk, hostname, iproute, jq, python3 >= 3.11, util-linux
Recommends:     aide, inotify-tools, lsof, net-tools, nmap, rkhunter

%description
SecureWatch runs local host checks, records structured security events,
and generates private JSON and HTML reports. The web dashboard is optional.

%prep

%build

%install
mkdir -p %{buildroot}
cp -a %{securewatch_payload}/. %{buildroot}/

%files
%defattr(-,root,root,-)
%config(noreplace) /etc/securewatch/securewatch.conf
%license /usr/share/doc/securewatch/LICENSE
%doc /usr/share/doc/securewatch/README.md
/usr/bin/securewatch
/usr/lib/securewatch/VERSION
/usr/lib/securewatch/bin/securewatch
/usr/lib/securewatch/modules/*.sh
/usr/lib/securewatch/python/*.py
/usr/lib/securewatch/scripts/*.sh
/usr/lib/systemd/system/securewatch.service
/usr/lib/systemd/system/securewatch.timer
%attr(0700,root,root) %dir /var/lib/securewatch
%attr(0700,root,root) %dir /var/lib/securewatch/logs
%attr(0700,root,root) %dir /var/lib/securewatch/reports
%attr(0700,root,root) %dir /var/lib/securewatch/state

%post
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now securewatch.timer securewatch.service >/dev/null 2>&1 || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || :
fi
