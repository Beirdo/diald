/*
 * proxy_dev.c - Proxy interface specific code in diald.
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


static char proxy_dev_ifbase[9];
static char *current_proxy;
static char hdr[ETH_HLEN + 2 - sizeof(unsigned short)];


static void
proxy_dev_send(unsigned short wprot, unsigned char *p, size_t len)
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
proxy_dev_recv(unsigned char *p, size_t len)
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
proxy_dev_init(char *proxydev)
{
    int n;

    current_proxy = proxydev;

    n = strcspn(proxydev, "0123456789" );
    proxy_dev.ifunit = atoi(proxydev + n);
    if (n > sizeof(proxy_dev_ifbase)-1)
		n = sizeof(proxy_dev_ifbase)-1;
    strncpy(proxy_dev_ifbase, proxydev, n);
    proxy_dev_ifbase[n] = '\0';

#ifdef HAVE_AF_PACKET
    if (af_packet && (n = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0)
#endif
    {
	af_packet = 0;
	if ((n = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
	    mon_syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
	    return -1;
	}
    }

#ifdef HAVE_AF_PACKET
    if (af_packet) {
	struct ifreq ifr;
	struct sockaddr_ll to;

	strncpy(ifr.ifr_name, proxydev, IFNAMSIZ);
	if (ioctl(n, SIOCGIFINDEX, &ifr) < 0) {
	    mon_syslog(LOG_ERR, "Proxy interface %s: %m", proxydev);
	    close(n);
	    return -1;
	}
	memset(&to, 0, sizeof(to));
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = ifr.ifr_ifindex;
	if (bind(n, (struct sockaddr *)&to, sizeof(to)) < 0) {
	    mon_syslog(LOG_ERR, "Bind to proxy interface %s: %m", proxydev);
	    close(n);
	    return -1;
	}
    } else
#endif
    {
	struct sockaddr to;

	to.sa_family = AF_INET;
	strcpy(to.sa_data, proxydev);
	if (bind(n, (struct sockaddr *)&to, sizeof(to)) < 0) {
	    mon_syslog(LOG_ERR, "Bind to proxy interface %s: %m", proxydev);
	    close(n);
	    return -1;
	}
    }

    return n;
}


static void
proxy_dev_start()
{
    if (current_dev && !strcmp(current_proxy, current_dev)) {
	close(proxy_fd);
	if ((proxy_fd = proxy_dev_init(current_proxy)) < 0)
	    return;
    }

    if (!blocked || blocked_route)
	iface_start(proxy_dev.iftype, proxy_dev.ifunit,
	    orig_local_ip, orig_remote_ip);
}


static void
proxy_dev_stop()
{
    if (current_dev && !strcmp(current_proxy, current_dev)) {
	close(proxy_fd);
	proxy_fd = -1;
    }
    iface_stop(proxy_dev.iftype, proxy_dev.ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_dev_close()
{
    close(proxy_fd);
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}


static void
proxy_dev_release()
{
    proxy_dev_stop();
    proxy_dev_close();
}


struct proxy proxy_dev = {
	proxy_dev_ifbase, 0,
	proxy_dev_send,
	proxy_dev_recv,
	proxy_dev_init,
	proxy_dev_start,
	proxy_dev_stop,
	proxy_dev_close,
	proxy_dev_release
};
