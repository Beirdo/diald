/*
 * dev.c - An ethernet-like device (e.g. ISDN).
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
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
    ulong laddr = 0, raddr = 0;
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
	sprintf(ifr.ifr_name, current_dev);
	if (ioctl(snoopfd, SIOCGIFFLAGS, (caddr_t) &ifr) == -1) {
	    mon_syslog(LOG_ERR,
		"failed to read interface status from device %s: %m",
		current_dev);
	    return 0;
	}
	if (!(ifr.ifr_flags & IFF_UP))
	    return 0;	/* interface is not up yet */

	if (route_wait) {
            /* set the initial rx counter once the link is up */
            if (rx_count == -1) rx_count = dev_rx_count();

            /* check if we got the routing packet yet */
            if (dev_rx_count() == rx_count) return 0;
	}

	/* Ok, the interface is up, grab the addresses. */
	if (ioctl(snoopfd, SIOCGIFADDR, (caddr_t) &ifr) == -1)
	    mon_syslog(LOG_ERR,
		"failed to get local address from device %s: %m",
		current_dev);
	else
       	    laddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	if (ioctl(snoopfd, SIOCGIFDSTADDR, (caddr_t) &ifr) == -1) 
	    mon_syslog(LOG_ERR,
		"failed to get remote address from device %s: %m",
		current_dev);
	else
	    raddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	/* KLUDGE 1:
	 * If we do not have a valid remote address yet the interface
	 * is not really up. We assume that a non-blocking connect
	 * method was used (e.g. isdnctrl dial ...) and that something
	 * like ippp will reconfigure the interface when it comes up.
	 */
	if (raddr == INADDR_ANY || raddr == INADDR_LOOPBACK)
	    return 0;

	if (dynamic_addrs) {
	    /* only do the configuration in dynamic mode. */
	    struct in_addr addr;
	    addr.s_addr = raddr;
	    if (remote_ip) free(remote_ip);
	    remote_ip = strdup(inet_ntoa(addr));
	    addr.s_addr = laddr;
	    if (local_ip) free(local_ip);
	    local_ip = strdup(inet_ntoa(addr));
	    local_addr = laddr;
	    mon_syslog(LOG_INFO,"New addresses: local %s, remote %s.",
		local_ip,remote_ip);
	}

	if (!do_reroute
	&& (dynamic_addrs || (blocked && !blocked_route))) {
	    proxy_config(local_ip,remote_ip);
	    set_ptp("sl", proxy_iface, local_ip, remote_ip, metric+1);
	    del_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,metric+1);
	    add_routes("sl",proxy_iface,local_ip,remote_ip,metric+1); 
	}

	/* Set the ptp routing for the new interface */
	/* this was moved from about 15 lines above by ajy so that for */
	/* dynamic addresses, we have the remote address when we make */
	/* the call to setup the route */
	set_ptp(device_node, link_iface, local_ip, remote_ip, metric+0);

	if (do_reroute) {
             add_routes(device_node,link_iface,local_ip,remote_ip,metric+0);
	     del_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,metric+1);
	}

        return 1;
}

int dev_dead()
{
    if (dead)
	dev_reroute();
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
    /* FIXME: There should be something here that actually can shut
     * down whatever is driving the ether device, or at least try.
     * [The trick used by the ISDN people seems to be to hang up
     * in the delroute scripts. The ip-down scripts make sense
     * for this as well. This might well be good enough.]
     */
    dead = 1;
}

void dev_reroute()
{
    /* Restore the original proxy routing */
    proxy_config(orig_local_ip,orig_remote_ip);
    if (blocked && !blocked_route)
	del_ptp("sl", proxy_iface, orig_local_ip, orig_remote_ip, metric+1);
    else {
	set_ptp("sl", proxy_iface, orig_local_ip, orig_remote_ip, metric+1);
	add_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,metric+1);
    }
    local_addr = inet_addr(orig_local_ip);

    /* Kill the alternate routing */
    if (do_reroute && link_iface != -1)
        del_routes(device_node,link_iface,local_ip,remote_ip,metric+0);
    link_iface = -1;
}

/* Dummy proc. This should never get called */
void dev_kill()
{
}

/* Dummy proc. This should never get called */
void dev_zombie()
{
}
