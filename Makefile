# ------------------ USER CONFIGURABLE SETTINGS ---------------------------
# The directories where files will be installed, you may want to change these.

# dctrl goes here
BINDIR=/usr/bin
# diald goes here
SBINDIR=/usr/sbin
# the manual page goes here
MANDIR=/usr/man
# the configuration files go here
LIBDIR=/usr/lib/diald

# Compiler flags. Note that with gcc 2.5.8 using -g without -O
# will cause it to miscompile the filter parsing code.
# Also note that later versions of gcc may generate bad code
# with the -fomit-frame-pointer option.
#CFLAGS = -O -g -Wall -fomit-frame-pointer -pipe
CFLAGS = -O2 -g -Wall -pipe

# If you are using gcc 2.5.8 this will get you QMAGIC executables
# later versions of gcc do this by default.
#LDFLAGS = -Xlinker -qmagic


#Moderately paranoid CFLAGS (this is moderately useful):
#CFLAGS = -Wall -Wtraditional -Wshadow -Wpointer-arith \
#	-Wcast-qual -Wcast-align -Wconversion \
#        -Wstrict-prototypes -Wnested-externs -Winline \
#	-Waggregate-return \
#	-O2 -fomit-frame-pointer -pipe

# Totally paranoid CFLAGS: (Only useful if you like warning messages:-))
#CFLAGS = -Wall -Wtraditional -Wshadow -Wpointer-arith \
#        -Wbad-function-cast -Wcast-qual -Wcast-align \
#        -Wwrite-strings -Wconversion -Waggregate-return \
#        -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
#        -Wredundant-decls -Wnested-externs -Winline \
#        -O2 -fomit-frame-pointer -pipe


# ------------------ END OF USER CONFIGURATIONS ---------------------------

OBJFILES=diald.o options.o modem.o filter.o slip.o lock.o ppp.o dev.o \
	proxyarp.o fsm.o timer.o parse.o buffer.o proxy.o \
	route.o bufio.o utils.o firewall.o
SOURCEFILES=diald.c options.c modem.c filter.c slip.c lock.c ppp.c dev.c \
	proxyarp.c fsm.c timer.c firewall.c parse.c buffer.c proxy.c route.c \
	bufio.c utils.c bin patches config
HFILES=config.h diald.h firewall.h fsm.h version.h timer.h bufio.h
DOCFILES=CHANGES README BUGS THANKS LICENSE doc/diald.man doc/diald-faq.txt \
	doc/dctrl.man doc/diald-examples.man doc/diald-control.man \
	doc/diald-monitor.man
CONTRIBFILES=contrib
DISTFILES=Makefile $(SOURCEFILES) $(HFILES) $(DOCFILES) $(CONTRIBFILES)

diald: $(OBJFILES)
	$(CC) $(LDFLAGS) -o diald $(OBJFILES)

install: diald
	-mkdir -p ${DESTDIR}${BINDIR}
	install -o root -g bin bin/dctrl ${DESTDIR}${BINDIR}/dctrl
	-mkdir -p ${DESTDIR}${SBINDIR}
	install -o root -g bin diald ${DESTDIR}${SBINDIR}/diald
	-mkdir -p ${DESTDIR}${MANDIR}/man1 ${DESTDIR}${MANDIR}/man5 \
		${DESTDIR}${MANDIR}/man8
	install -o root -g bin -m 0644 doc/diald.man ${DESTDIR}${MANDIR}/man8/diald.8
	install -o root -g bin -m 0644 doc/dctrl.man ${DESTDIR}${MANDIR}/man1/dctrl.1
	install -o root -g bin -m 0644 doc/diald-examples.man ${DESTDIR}${MANDIR}/man5/diald-examples.5
	install -o root -g bin -m 0644 doc/diald-control.man ${DESTDIR}${MANDIR}/man5/diald-control.5
	install -o root -g bin -m 0644 doc/diald-monitor.man ${DESTDIR}${MANDIR}/man5/diald-monitor.5
	-mkdir -p ${DESTDIR}${LIBDIR}
	install -o root -g bin -m 0644 config/diald.defs ${DESTDIR}${LIBDIR}/diald.defs
	install -o root -g bin -m 0644 config/standard.filter ${DESTDIR}${LIBDIR}/standard.filter
	install -o root -g bin bin/connect ${DESTDIR}${LIBDIR}/connect

clean:
	rm -f *.o diald

dist: $(DISTFILES)
	d=diald-`sed -e '/VERSION/!d' -e 's/[^0-9.]*\([0-9.a]*\).*/\1/' -e q version.h` ; \
	rm -f ../$$d; \
	ln -s `pwd` ../$$d; \
	cd ..; \
	files=""; \
	for f in $(DISTFILES); do files="$$files $$d/$$f"; done; \
	tar chof $$d/$$d.tar $$files; \
	gzip $$d/$$d.tar ; \
	rm -f $$d

depend:
	$(CPP) -M *.c > .depend

#
# include a dependency file if one exists
#
ifeq (.depend,$(wildcard .depend))
include .depend
endif
