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

#include "proxy.h"


struct proxy *proxy;


void
send_packet(unsigned short wprot, unsigned char *p, size_t len)
{
	proxy->send(wprot, p, len);
}


int
recv_packet(unsigned char *p, size_t len)
{
	return proxy->recv(p, len);
}


void
proxy_start()
{
	proxy->start();
}


int
proxy_init(char *proxydev)
{
	int fd;

	if (proxydev) {
		proxy = &proxy_dev;
		return proxy->init(proxydev);
	}

	proxy = &proxy_tap;
	if ((fd = proxy->init(NULL)) >= 0)
		return fd;
	proxy = &proxy_slip;
	if ((fd = proxy->init(NULL)) >= 0)
		return fd;
	mon_syslog(LOG_ERR, "Unable to get a proxy interface."
				" Manual control only.");
	return -1;
}


void
proxy_close()
{
	proxy->close();
}


void
proxy_release()
{
	proxy->release();
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
