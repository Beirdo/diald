Vendor:       Open Source Community
Distribution: All
Packager:     Mike Jagdis <jaggy@purplet.demon.co.uk>

Group:        Networking/Daemons
Name:         diald
Version:      1.0
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
%attr (0755, root, root) /usr/sbin/diald
%attr (0755, root, root) /usr/bin/dctrl
%attr (0644, root, root) /usr/lib/diald/*.gif
