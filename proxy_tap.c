/*
 * proxy_tap.c - Proxy interface specific code in diald.
 *		 The proxy interface is used to monitor packets
 *		 when the physical link is down.
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


static char *proxy_lock;
static char hdr[ETH_HLEN + 2 - sizeof(unsigned short)];


static void proxy_tap_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len);
static int proxy_tap_recv(proxy_t *proxy, unsigned char *p, size_t len);
static void proxy_tap_start(proxy_t *proxy);
static void proxy_tap_stop(proxy_t *proxy);
static void proxy_tap_close(proxy_t *proxy);
static void proxy_tap_release(proxy_t *proxy);
int proxy_tap_init(proxy_t *proxy, char *proxydev);


static void
proxy_tap_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len)
{
    struct msghdr msg;
    struct iovec msg_iov[3];

    /* This is only called to send a response to a received packet
     * therefore there must be a convenient header in hdr.
     */
    msg_iov[0].iov_base = hdr;
    msg_iov[0].iov_len = sizeof(hdr);
    msg_iov[1].iov_base = &wprot;
    msg_iov[1].iov_len = sizeof(unsigned short);
    msg_iov[2].iov_base = p;
    msg_iov[2].iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = 2;

    sendmsg(proxy_fd, &msg, 0);
}


static int
proxy_tap_recv(proxy_t *proxy, unsigned char *p, size_t len)
{
    struct msghdr msg;
    struct iovec msg_iov[2];

    msg_iov[0].iov_base = hdr;
    msg_iov[0].iov_len = sizeof(hdr);
    msg_iov[1].iov_base = p;
    msg_iov[1].iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = 2;

    len = recvmsg(proxy_fd, &msg, 0);
    return (len < 0 ? 0 : len - sizeof(hdr));
}


static void
proxy_tap_start(proxy_t *proxy)
{
    iface_start(proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_tap_stop(proxy_t *proxy)
{
    iface_stop(proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_tap_close(proxy_t *proxy)
{
    close(proxy_fd);
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}


static void
proxy_tap_release(proxy_t *proxy)
{
    proxy_tap_stop(proxy);
    proxy_tap_close(proxy);
    unlock(proxy_lock);
}


int
proxy_tap_init(proxy_t *proxy, char *proxydev)
{
    for (proxy->ifunit=0; proxy->ifunit<16; proxy->ifunit++) {
	int d;
	char buf[16];
	struct sockaddr_nl nl;
	struct ifreq ifr;

	sprintf(buf, "tap%d", proxy->ifunit);
	if (!(proxy_lock = lock(buf)))
	    continue;

	d = socket(AF_NETLINK, SOCK_RAW, NETLINK_TAPBASE+proxy->ifunit);
	if (d < 0)
	    goto unlock;

	/* We have a socket but does the interface actually *exist*? */
	strncpy(ifr.ifr_name, buf, IFNAMSIZ);
	if (ioctl(d, SIOCGIFINDEX, &ifr) < 0)
	    goto close_and_unlock;

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	nl.nl_groups = ~0;
	if (bind(d, (struct sockaddr *)&nl, sizeof(nl)) < 0)
	    goto close_and_unlock;

	if (debug&DEBUG_VERBOSE)
	    mon_syslog(LOG_INFO,
		"Proxy device established on interface %s%d",
		proxy->iftype, proxy->ifunit);
	strcpy(proxy->iftype, "tap");
	proxy->send = proxy_tap_send;
	proxy->recv = proxy_tap_recv;
	proxy->init = proxy_tap_init;
	proxy->start = proxy_tap_start;
	proxy->stop = proxy_tap_stop;
	proxy->close = proxy_tap_close;
	proxy->release = proxy_tap_release;
	return d;

close_and_unlock:
	close(d);
unlock:
	unlock(proxy_lock);
    }

    return -1;
}
