/*
 * dev.c - An ethernet-like device (e.g. ISDN).
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * Patched from ppp.c to support ethernet devices
 * like isdn4linux 
 * Wim Bonis bonis@kiss.de
 *
 * Further modifications by Eric Schenk to merge into diald mainline
 * sources.
 *
 */

#include "diald.h"

static char device_node[9];

static int dead = 1;

/* internal flag to shortcut repeated calls to setaddr */
static int rx_count = -1;

void dev_start()
{
    link_iface = -1 ;
    rx_count = -1;
    mon_syslog(LOG_INFO, "Open device %s", current_dev);
    dead = 0;
}

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)                     \
    memset ((char *) &(addr), '\0', sizeof(addr));      \
    addr.sa_family = (family);


/*
 * Find the interface number of the ppp device that pppd opened up and
 * do any routing we might need to do.
 * If pppd has not yet opened the device, then return 0, else return 1.
 */

int dev_set_addrs()
{
    ulong laddr = 0, raddr = 0, baddr = 0;
    struct ifreq   ifr; 

    /* Try to get the interface number if we don't know it yet. */
    if (link_iface == -1) {
	int n;
	n = strcspn(current_dev, "0123456789" );
	link_iface = atoi(current_dev + n);
	if (n > sizeof(device_node)-1)
		n = sizeof(device_node)-1;
	strncpy(device_node, current_dev, n);
	device_node[n] = '\0';
    }


	SET_SA_FAMILY (ifr.ifr_addr,    AF_INET); 
	SET_SA_FAMILY (ifr.ifr_dstaddr, AF_INET); 
	SET_SA_FAMILY (ifr.ifr_netmask, AF_INET); 
	strncpy(ifr.ifr_name, current_dev, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t) &ifr) == -1) {
	    mon_syslog(LOG_ERR,
		"failed to read interface status from device %s: %m",
		current_dev);
	    return 0;
	}
	if ((ifr.ifr_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
	    return 0;	/* interface is not up and running yet */

	if (route_wait) {
            /* set the initial rx counter once the link is up */
            if (rx_count == -1) rx_count = dev_rx_count();

            /* check if we got the routing packet yet */
            if (dev_rx_count() == rx_count) return 0;
	}

	/* Ok, the interface is up, grab the addresses. */
	if (ioctl(sockfd, SIOCGIFADDR, (caddr_t) &ifr) == -1)
	    mon_syslog(LOG_ERR,
		"failed to get local address from device %s: %m",
		current_dev);
	else
       	    laddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	if (ioctl(sockfd, SIOCGIFDSTADDR, (caddr_t) &ifr) == -1) 
	    mon_syslog(LOG_ERR,
		"failed to get remote address from device %s: %m",
		current_dev);
	else
	    raddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	if (ioctl(sockfd, SIOCGIFBRDADDR, (caddr_t) &ifr) == -1) 
	    mon_syslog(LOG_ERR,
		"failed to get broadcast address from device %s: %m",
		current_dev);
	else
	    baddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	/* KLUDGE 1:
	 * If we do not have a valid remote address yet the interface
	 * is not really up. We assume that a non-blocking connect
	 * method was used (e.g. isdnctrl dial ...) and that something
	 * like ippp will reconfigure the interface when it comes up.
	 */
	if (baddr == INADDR_ANY
	&& (raddr == INADDR_ANY || raddr == INADDR_LOOPBACK))
	    return 0;

	if (dynamic_addrs) {
	    /* only do the configuration in dynamic mode. */
	    struct in_addr addr;
	    addr.s_addr = baddr;
	    if (broadcast_ip) free(broadcast_ip);
	    broadcast_ip = strdup(inet_ntoa(addr));
	    addr.s_addr = raddr;
	    if (remote_ip) free(remote_ip);
	    remote_ip = strdup(inet_ntoa(addr));
	    addr.s_addr = laddr;
	    if (local_ip) free(local_ip);
	    local_ip = strdup(inet_ntoa(addr));
	    local_addr = laddr;
	    if (dynamic_addrs > 1) {
		if (orig_broadcast_ip) free(orig_broadcast_ip);
		orig_broadcast_ip = strdup(broadcast_ip);
		if (orig_remote_ip) free(orig_remote_ip);
		orig_remote_ip = strdup(remote_ip);
		if (orig_local_ip) free(orig_local_ip);
		orig_local_ip = strdup(local_ip);
	    }
	    mon_syslog(LOG_INFO, "New addresses: local %s%s%s%s%s",
		local_ip,
		remote_ip ? ", remote " : "",
		remote_ip ? remote_ip : "",
		broadcast_ip ? ", broadcast " : "",
		broadcast_ip ? broadcast_ip : "");
	}

	iface_start("link", device_node, link_iface,
	    local_ip, remote_ip, broadcast_ip);
	if (proxy.stop)
	    proxy.stop(&proxy);

        return 1;
}

int dev_dead()
{
    /* If we think the interface is not dead we check its flags
     * to see if it is still up and running.
     */
    if (!dead) {
	struct ifreq ifr;
	strncpy(ifr.ifr_name, current_dev, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t) &ifr) == -1
	|| (ifr.ifr_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
	    dead = 1;
    }
    return (dead);
}

int dev_rx_count()
{
    char buf[128];
    int packets = 0;
    FILE *fp;
    sprintf(buf,"%s %s",path_ifconfig, current_dev);
    if ((fp = popen(buf,"r"))==NULL) {
        mon_syslog(LOG_ERR,"Could not run command '%s': %m",buf);
        return 0;       /* assume half dead in this case... */
    }

    while (fgets(buf,128,fp)) {
        if (sscanf(buf," RX packets:%d",&packets) == 1) {
            break;
        }
    }
    fclose(fp);
    return packets;
}

void dev_stop()
{
    /* If there is a requesting pid we assume it controls the
     * interface in some way and kill it now. But we don't
     * know this is the case...
     */
    if (!req_pid)
	dead = 1;
    else if (kill(req_pid, SIGINT) == -1 && errno == ESRCH) {
	req_pid = 0;
	dead = 1;
    }
}

void dev_reroute()
{
    /* Restore the original proxy. */
    if (proxy.start && (!blocked || blocked_route))
	proxy.start(&proxy);
    local_addr = (orig_local_ip ? inet_addr(orig_local_ip) : 0);

    /* Kill the alternate routing */
    if (link_iface != -1) {
	iface_stop("link", device_node, link_iface,
	    local_ip, remote_ip, broadcast_ip);
	/* We do not down dev interfaces here. Things like ISDN
	 * require the interface to be up to receive incoming calls.
	 * If this is not what you want you can do it in a disconnect
	 * script.
	 */
	link_iface = -1;
    }
}

void dev_kill()
{
    /* If there is a requesting pid we assume it controls the
     * interface in some way and kill it now. But we don't
     * know this is the case...
     */
    if (!req_pid)
	dead = 1;
    else if (kill(req_pid, SIGKILL) == -1 && errno == ESRCH) {
	req_pid = 0;
	dead = 1;
    }
}

void dev_zombie()
{
    /* Maybe the requesting pid didn't control the interface
     * in any way. Maybe the interface is supposed to stay
     * up for some reason (ISDN for instance). At this stage
     * we have little choice but to pretend it is dead.
     */
    dead = 1;
}
