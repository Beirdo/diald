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

char *proxy_iftype = "tap";

static char *proxy_lock;
static char hdr[ETH_HLEN + 2 - sizeof(unsigned short)];


void send_packet(unsigned short wprot, unsigned char *p, size_t len)
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


int recv_packet(unsigned char *p, size_t len)
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


void proxy_up(void)
{
    /* Mark the interface as up */
    if (!blocked || blocked_route)
	iface_start(proxy_iftype, proxy_ifunit, orig_local_ip, orig_remote_ip);
}


int proxy_open()
{
    for (proxy_ifunit=0; proxy_ifunit<16; proxy_ifunit++) {
	char buf[16];

	sprintf(buf, "%s%d", proxy_iftype, proxy_ifunit);
	if (!(proxy_lock = lock(buf)))
	    continue;

	proxy_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TAPBASE+proxy_ifunit);
	if (proxy_fd >= 0) {
	    struct sockaddr_nl nl;

	    memset(&nl, 0, sizeof(nl));
	    nl.nl_family = AF_NETLINK;
	    nl.nl_groups = ~0;
	    if (bind(proxy_fd, (struct sockaddr *)&nl, sizeof(nl)) >= 0)
		return proxy_fd;
	}

	close(proxy_fd);
	unlock(proxy_lock);
    }

    mon_syslog(LOG_ERR, "No ethertap device available for proxy");
    die(1);
    /* NOTREACHED */
   return -1;
}

void proxy_close()
{
    close(proxy_fd);
    /* Do not remove the lock file here. If we do every time we fork
     * a child we drop the lock. Instead we just let the lock go stale
     * when we have finished. We should handle this better...
     */
}

void proxy_release()
{
    iface_stop(proxy_iftype, proxy_ifunit, orig_local_ip, orig_remote_ip);
    proxy_close();
    unlock(proxy_lock);
}

void run_state_script(char *name, char *script, int background)
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


#if 0
int
main(int argc, char *argv[])
{
	struct iphdr *ip;
	int i, j;
	unsigned char buf[256];

	proxy_up();

	ip = (struct iphdr *)buf;
	while (1) {
		int l = recv_packet(buf, sizeof(buf));
		if (l <= 0)
			continue;
		fprintf(stderr, "packet: len=%d  proto=%d  src=0x%08lx  dst=0x%08lx\n",
			l, ip->protocol, ip->saddr, ip->daddr);
		for (j=0; j<l; j+=16) {
			fprintf(stderr, "        ");
			for (i=0; i<16 && j+i<l; i++)
				fprintf(stderr, "%02x ", buf[j+i]);
			fprintf(stderr, "\n");
		}
	}
}
#endif
