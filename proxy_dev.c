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


static char *current_proxy;
#ifdef HAVE_AF_PACKET
static int current_proxy_index;
#endif


static void proxy_dev_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len);
static int proxy_dev_recv(proxy_t *proxy, unsigned char *p, size_t len);
static void proxy_dev_start(proxy_t *proxy);
static void proxy_dev_stop(proxy_t *proxy);
static void proxy_dev_close(proxy_t *proxy);
static void proxy_dev_release(proxy_t *proxy);
int proxy_dev_init(proxy_t *proxy, char *proxydev);


static void
proxy_dev_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len)
{
    struct sockaddr *to;
    struct sockaddr_pkt sp;
#ifdef HAVE_AF_PACKET
    struct sockaddr_ll sl;
    size_t to_len;

    if (af_packet) {
	memset(&sl, 0, sizeof(sl));
	sl.sll_family = AF_PACKET;
	sl.sll_protocol = wprot;
	sl.sll_ifindex = current_proxy_index;
	to = (struct sockaddr *)&sl;
	to_len = sizeof(sl);
    } else
#endif
    {
	memset(&sp, 0, sizeof(sp));
	sp.spkt_family = AF_INET;
	strcpy(sp.spkt_device, current_proxy);
	sp.spkt_protocol = wprot;
	to = (struct sockaddr *)&sp;
	to_len = sizeof(sp);
    }

    sendto(proxy->fd, p, len, 0, to, to_len);
}


static int
proxy_dev_recv(proxy_t *proxy, unsigned char *p, size_t len)
{
    union {
	struct sockaddr sa;
#ifdef HAVE_AF_PACKET
	struct sockaddr_ll sl;
#endif
    } from;
    size_t flen = sizeof(from);
    unsigned char *q = p + sizeof(unsigned short);
    size_t qlen = len - sizeof(unsigned short);

    len = recvfrom(proxy->fd, q, qlen, 0, (struct sockaddr *)&from, &flen);
    if (len <= 0)
	return 0;

    /* FIXME: We only care about packets *sent* on the interface
     * not those received. But how can we tell for non AF_PACKET
     * sockets?
     */
#ifdef HAVE_AF_PACKET
    if ((af_packet && from.sl.sll_pkttype == PACKET_OUTGOING))
	return 0;
#endif

    *(unsigned short *)p =
#ifdef HAVE_AF_PACKET
	af_packet ? from.sl.sll_protocol :
#endif
	htons(ETH_P_IP);
    return len + sizeof(unsigned short);
}


static void
proxy_dev_start(proxy_t *proxy)
{
    if (current_dev && !strcmp(current_proxy, current_dev)) {
	if (proxy->fd >= 0) {
	    close(proxy->fd);
	    proxy->fd = -1;
	}
	proxy_dev_init(proxy, current_proxy);
	return;
    }

    iface_start("proxy", proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_dev_stop(proxy_t *proxy)
{
    if (current_dev && !strcmp(current_proxy, current_dev)) {
	if (proxy->fd >= 0) {
	    close(proxy->fd);
	    proxy->fd = -1;
	}
	return;
    }

    iface_stop("proxy", proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip);
}


static void
proxy_dev_close(proxy_t *proxy)
{
    if (proxy->fd >= 0) {
	close(proxy->fd);
	proxy->fd = -1;
    }
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}


static void
proxy_dev_release(proxy_t *proxy)
{
    proxy_dev_stop(proxy);
    proxy_dev_close(proxy);
}


int
proxy_dev_init(proxy_t *proxy, char *proxydev)
{
    int d, n;

#ifdef HAVE_AF_PACKET
    if (af_packet && (d = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0)
#endif
    {
	af_packet = 0;
	if ((d = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
	    mon_syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
	    return -1;
	}
    }

#ifdef HAVE_AF_PACKET
    if (af_packet) {
	struct ifreq ifr;
	struct sockaddr_ll to;

	strncpy(ifr.ifr_name, proxydev, IFNAMSIZ);
	if (ioctl(d, SIOCGIFINDEX, &ifr) < 0) {
	    mon_syslog(LOG_ERR, "Proxy interface %s: %m", proxydev);
	    close(d);
	    return -1;
	}
	current_proxy_index = ifr.ifr_ifindex;
	memset(&to, 0, sizeof(to));
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = ifr.ifr_ifindex;
	if (bind(d, (struct sockaddr *)&to, sizeof(to)) < 0) {
	    mon_syslog(LOG_ERR, "Bind to proxy interface %s: %m", proxydev);
	    close(d);
	    return -1;
	}
    } else
#endif
    {
	struct sockaddr to;

	to.sa_family = AF_INET;
	strcpy(to.sa_data, proxydev);
	if (bind(d, (struct sockaddr *)&to, sizeof(to)) < 0) {
	    mon_syslog(LOG_ERR, "Bind to proxy interface %s: %m", proxydev);
	    close(d);
	    return -1;
	}
    }

    current_proxy = proxydev;
    n = strcspn(proxydev, "0123456789" );
    proxy->ifunit = atoi(proxydev + n);
    if (n > sizeof(proxy->iftype)-1)
		n = sizeof(proxy->iftype)-1;
    strncpy(proxy->iftype, proxydev, n);
    proxy->iftype[n] = '\0';
    proxy->send = proxy_dev_send;
    proxy->recv = proxy_dev_recv;
    proxy->init = proxy_dev_init;
    proxy->start = proxy_dev_start;
    proxy->stop = proxy_dev_stop;
    proxy->close = proxy_dev_close;
    proxy->release = proxy_dev_release;
    proxy->fd = d;
    return n;
}
