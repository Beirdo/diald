/*
 * log.c - Message logging to monitors and syslog.
 *
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>

#include <diald.h>


static char *
xstrerror(int n)
{
    static char	buf[30];

    if (n >= 0 && n < sys_nerr)
	return (char *)sys_errlist[n];
    sprintf(buf, "Error code %d\n", n);
    return buf;
}


void
mon_syslog(int pri, char *fmt, ...)
{
	va_list ap;
	int saved_errno;
	int l1, l2;
	char c, *p, *q, fmt2[1024], buf[2048];

	saved_errno = errno;

	va_start(ap, fmt);

	l1 = snprintf(fmt2, sizeof(fmt2)-1,
		"<%c>MESSAGE\n%s ", pri+'0', cdate(time(0)));
	for (p = fmt2+l1; (c = *fmt) && p < fmt2+sizeof(fmt2)-2; fmt++) {
		if (c == '%' && fmt[1] == 'm') {
			fmt++;
			for (q = xstrerror(saved_errno); p < fmt2+sizeof(fmt2)-2; p++,q++)
				*p = *q;
		} else {
			*(p++) = c;
		}
	}
	*p = '\0';

	l2 = vsnprintf(buf, sizeof(buf)-2, fmt2, ap);

	va_end(ap);

	syslog(pri, "%s", buf+l1);

	buf[l2++] = '\n';
	buf[l2] = '\0';
	mon_write(MONITOR_MESSAGE, buf, l2);
}
