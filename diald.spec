Vendor:       Open Source Community
Distribution: All
Packager:     Mike Jagdis <jaggy@purplet.demon.co.uk>

Group:        Networking/Daemons
Name:         diald
Version:      2.0
Release:      1
Copyright:    GNU General Public License

Summary:      On demand link manager
#URL:

BuildRoot:    /tmp/diald-root
Source:       diald-%{version}.tar.gz

%description
On demand link manager.

%prep
%setup

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
	--mandir=%{_mandir}
make

%install
make install DESTDIR="$RPM_BUILD_ROOT"

%clean
rm -rf "$RPM_BUILD_ROOT"


%files
%doc BUGS CHANGES LICENSE NOTES TODO TODO.budget doc/diald-faq.txt
%doc README README.ethertap README.masq README.pam
%doc %{_mandir}/man1/dctrl.1
%doc %{_mandir}/man5/diald-examples.5
%doc %{_mandir}/man5/diald-control.5
%doc %{_mandir}/man5/diald-monitor.5
%doc %{_mandir}/man8/diald.8
/usr/sbin/diald
/usr/bin/dctrl
/etc/pam.d/diald
/usr/share/diald/dctrl/*.gif
/usr/share/diald/diald.defs
/usr/share/diald/standard.filter
/usr/share/diald/dynamic.filter
/usr/share/diald/connect
/usr/share/diald/disconnect
/usr/share/diald/device/dhcp
/usr/share/diald/device/dhcp.hangup
/usr/share/diald/device/isdn
/usr/share/diald/device/isdn.hangup
/usr/share/diald/modem/generic
/usr/share/diald/login/demon
/usr/share/diald/login/shell-generic
