/*
 * proxy_tun.c - Proxy interface specific code in diald.
 *		 The proxy interface is used to monitor packets
 *		 when the physical link is down.
 *
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>


#ifdef TUNTAP

#include <sys/uio.h>
#include <linux/if_tun.h>

#include <netlink.h>


static int proxy_tun_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len);
static int proxy_tun_recv(proxy_t *proxy, unsigned char *p, size_t len);
static void proxy_tun_start(proxy_t *proxy);
static void proxy_tun_stop(proxy_t *proxy);
static void proxy_tun_close(proxy_t *proxy);
static void proxy_tun_release(proxy_t *proxy);
int proxy_tun_init(proxy_t *proxy, char *proxydev);


static int
proxy_tun_send(proxy_t *proxy,
	unsigned short wprot, unsigned char *p, size_t len)
{
    struct tun_pi pi = { 0, wprot };
    struct msghdr msg;
    struct iovec msg_iov[2];

    msg_iov[0].iov_base = &pi;
    msg_iov[0].iov_len = sizeof(pi);
    msg_iov[1].iov_base = p;
    msg_iov[1].iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = 2;

    return sendmsg(proxy->fd, &msg, 0);
}


static int
proxy_tun_recv(proxy_t *proxy, unsigned char *p, size_t len)
{
    struct tun_pi pi;
    struct msghdr msg;
    struct iovec msg_iov[2];

    msg_iov[0].iov_base = &pi;
    msg_iov[0].iov_len = sizeof(pi);
    msg_iov[1].iov_base = p+2;
    msg_iov[1].iov_len = len-2;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = 2;

    len = recvmsg(proxy->fd, &msg, 0);
    if (len >= sizeof(pi)) {
	p[0] = pi.proto >> 8;
	p[1] = pi.proto & 0xff;
    }
    return (len < 0 ? 0 : len - sizeof(pi));
}


static void
proxy_tun_start(proxy_t *proxy)
{
    iface_start("proxy", proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip, orig_broadcast_ip, metric+1);
}


static void
proxy_tun_stop(proxy_t *proxy)
{
    iface_stop("proxy", proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip, orig_broadcast_ip, metric+1);
}


static void
proxy_tun_close(proxy_t *proxy)
{
    close(proxy->fd);
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}


static void
proxy_tun_release(proxy_t *proxy)
{
    proxy_tun_stop(proxy);
    iface_down("proxy", proxy->iftype, proxy->ifunit,
	orig_local_ip, orig_remote_ip, orig_broadcast_ip, metric+1);
    proxy_tun_close(proxy);
}


int
proxy_tun_init(proxy_t *proxy, char *proxydev)
{
    int d;
    struct ifreq ifr;

    if ((d = open("/dev/net/tun", O_RDWR)) < 0)
	goto fail;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    if (ioctl(d, TUNSETIFF, (void *)&ifr) < 0 )
	goto close_and_fail;

    fcntl(d, F_SETFD, FD_CLOEXEC);

    if (debug&DEBUG_VERBOSE)
	mon_syslog(LOG_INFO,
		"Proxy device established on interface %s",
		ifr.ifr_name);

    strncpy(proxy->iftype, ifr.ifr_name, 3);
    proxy->iftype[3] = '\0';
    proxy->ifunit = atol(ifr.ifr_name+3);
    proxy->send = proxy_tun_send;
    proxy->recv = proxy_tun_recv;
    proxy->init = proxy_tun_init;
    proxy->start = proxy_tun_start;
    proxy->stop = proxy_tun_stop;
    proxy->close = proxy_tun_close;
    proxy->release = proxy_tun_release;
    proxy->fd = d;
    return d;

close_and_fail:
    close(d);
fail:
    return -1;
}

#endif /* TUNTAP */
