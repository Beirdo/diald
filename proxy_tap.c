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

#include "proxy.h"


static char *proxy_lock;
static char hdr[ETH_HLEN + 2 - sizeof(unsigned short)];


static void
proxy_tap_send(unsigned short wprot, unsigned char *p, size_t len)
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
proxy_tap_recv(unsigned char *p, size_t len)
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


static int
proxy_tap_init(char *proxydev)
{
    for (proxy_tap.ifunit=0; proxy_tap.ifunit<16; proxy_tap.ifunit++) {
	char buf[16];

	sprintf(buf, "%s%d", proxy_tap.iftype, proxy_tap.ifunit);
	if (!(proxy_lock = lock(buf)))
	    continue;

	proxy_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TAPBASE+proxy_tap.ifunit);
	if (proxy_fd >= 0) {
	    struct sockaddr_nl nl;

	    memset(&nl, 0, sizeof(nl));
	    nl.nl_family = AF_NETLINK;
	    nl.nl_groups = ~0;
	    if (bind(proxy_fd, (struct sockaddr *)&nl, sizeof(nl)) >= 0) {
		if (debug&DEBUG_VERBOSE)
		    mon_syslog(LOG_INFO,
			"Proxy device established on interface %s%d",
			proxy_tap.iftype, proxy_tap.ifunit);
		return proxy_fd;
	    }
	}

	close(proxy_fd);
	unlock(proxy_lock);
    }

    return -1;
}


static void
proxy_tap_start()
{
    if (!blocked || blocked_route)
	iface_start(proxy_tap.iftype, proxy_tap.ifunit,
	    orig_local_ip, orig_remote_ip);
}


static void
proxy_tap_stop()
{
    iface_stop(proxy_tap.iftype, proxy_tap.ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_tap_close()
{
    close(proxy_fd);
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}

static void
proxy_tap_release()
{
    proxy_tap_stop();
    proxy_tap_close();
    unlock(proxy_lock);
}


struct proxy proxy_tap = {
	"tap", 0,
	proxy_tap_send,
	proxy_tap_recv,
	proxy_tap_init,
	proxy_tap_start,
	proxy_tap_stop,
	proxy_tap_close,
	proxy_tap_release
};
