/*
 * tap.c - Proxy interface specific code in diald.
 *	   The proxy interface is used to monitor packets
 *	   when the physical link is down.
 *
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"


int
send_packet(unsigned short wprot, unsigned char *p, size_t len)
{
	if (proxy.send)
		return proxy.send(&proxy, wprot, p, len);
	errno = -ENOSYS;
	return -1;
}


int
recv_packet(unsigned char *p, size_t len)
{
	return (proxy.recv
		? proxy.recv(&proxy, p, len)
		: 0);
}


void
proxy_start()
{
	if (proxy.start)
		proxy.start(&proxy);
}


void
proxy_stop()
{
	if (proxy.stop)
		proxy.stop(&proxy);
}


void
proxy_close()
{
	if (proxy.close)
		proxy.close(&proxy);
}


void
proxy_release()
{
	if (proxy.release)
		proxy.release(&proxy);
}


int
proxy_init(proxy_t *proxy, char *proxydev)
{
	int fd;

	proxy->ifunit = -1;
	proxy->send = NULL;
	proxy->recv = NULL;
	proxy->init = NULL;
	proxy->start = NULL;
	proxy->stop = NULL;
	proxy->close = NULL;
	proxy->release = NULL;

	if (proxydev) {
		if (!strcmp(proxydev, "none"))
			return 0;
		return proxy_dev_init(proxy, proxydev);
	}

#ifdef TUNTAP
	if ((fd = proxy_tun_init(proxy, NULL)) >= 0)
		return fd;
#endif

#ifdef AF_NETLINK
	if ((fd = proxy_tap_init(proxy, NULL)) >= 0)
		return fd;
#endif
	if ((fd = proxy_slip_init(proxy, NULL)) >= 0)
		return fd;
	mon_syslog(LOG_ERR, "Unable to get a proxy interface."
				" Manual control only.");
	return -1;
}
