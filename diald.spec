Vendor:		Open Source Community
Distribution:	All
Packager:	Mike Jagdis <jaggy@purplet.demon.co.uk>
Group:		System Environment/Daemons
Name:		diald
Version:	2.0
Release:	1
License:	GNU General Public License
Summary:	On demand link manager
URL:		http://diald.sourceforge.net
Source:		http://prdownloads.sourceforge.net/diald/diald-%{version}.tar.gz

%description
Diald is a daemon that provides on demand IP links via SLIP or
PPP. The purpose of diald is to make it transparently appear that
you have a permanent connection to a remote site. Diald sets up a
"proxy" device which stands in for the physical connection to a
remote site. It then monitors the proxy, waiting for packets to
arrive. When interesting packets arrive it will attempt to
establish the physical link to the remote site using either SLIP
or PPP, and if it succeeds it will forward traffic from the proxy
to the physical link. As well, diald will monitor traffic once
the physical link is up, and when it has determined that the link
is idle, the remote connection is terminated. The criteria for
bringing the link up and taking it down are configurable at run
time, and are based upon the type of traffic passing over the
link.

Install diald when you need a on-demand connection (esp. PPP to
Internet).
%prep
%setup

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
	--mandir=%{_mandir}
make

%install
make install DESTDIR="$RPM_BUILD_ROOT"
gzip -9fN %{_mandir}/man1/dctrl.1 \
	%{_mandir}/man5/diald-examples.5 \
	%{_mandir}/man5/diald-control.5 \
	%{_mandir}/man5/diald-monitor.5 \
	%{_mandir}/man8/diald.8

%clean
rm -rf "$RPM_BUILD_ROOT"


%files
%doc BUGS CHANGES LICENSE NOTES TODO TODO.budget doc/diald-faq.txt
%doc README README.ethertap README.masq README.pam
%{_mandir}/man1/dctrl.1.gz
%{_mandir}/man5/diald-examples.5.gz
%{_mandir}/man5/diald-control.5.gz
%{_mandir}/man5/diald-monitor.5.gz
%{_mandir}/man8/diald.8.gz
%attr (0644, root, root) /usr/share/diald/diald.defs
%attr (0644, root, root) /etc/pam.d/diald
%attr (0755, root, root) /usr/sbin/diald
%attr (0755, root, root) /usr/bin/dctrl
%attr (0644, root, root) /usr/share/diald/dctrl/*.gif
%attr (0644, root, root) /usr/share/diald/standard.filter
%attr (0644, root, root) /usr/share/diald/dynamic.filter
%attr (0755, root, root) /usr/share/diald/connect
%attr (0755, root, root) /usr/share/diald/disconnect
%attr (0755, root, root) /usr/share/diald/device/dhcp
%attr (0755, root, root) /usr/share/diald/device/dhcp.hangup
%attr (0755, root, root) /usr/share/diald/device/isdn
%attr (0755, root, root) /usr/share/diald/device/isdn.hangup
%attr (0755, root, root) /usr/share/diald/modem/generic
%attr (0755, root, root) /usr/share/diald/login/demon
%attr (0755, root, root) /usr/share/diald/login/shell-generic
