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

#include <sys/uio.h>
#include <netinet/if_ether.h>
#include <linux/types.h>
#include <linux/netlink.h>


void
send_packet(unsigned short wprot, unsigned char *p, size_t len)
{
	if (proxy.send)
		proxy.send(&proxy, wprot, p, len);
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

	if (proxydev)
		return proxy_dev_init(proxy, proxydev);

	if ((fd = proxy_tap_init(proxy, NULL)) >= 0)
		return fd;
	if ((fd = proxy_slip_init(proxy, NULL)) >= 0)
		return fd;
	mon_syslog(LOG_ERR, "Unable to get a proxy interface."
				" Manual control only.");
	proxy->ifunit = -1;
	proxy->send = NULL;
	proxy->recv = NULL;
	proxy->init = NULL;
	proxy->start = NULL;
	proxy->stop = NULL;
	proxy->close = NULL;
	proxy->release = NULL;
	return -1;
}


void
run_state_script(char *name, char *script, int background)
{
    char buf[128];

    snprintf(buf, sizeof(buf)-1, "%s %s %s %s %s",
	script,
	snoop_dev,
	netmask ? netmask : "255.255.255.255",
	local_ip,
	remote_ip);
    buf[sizeof(buf)-1] = '\0';

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_INFO,"running %s script '%s'", name, buf);

    if (background)
	background_system(buf);
    else
	system(buf);
}
