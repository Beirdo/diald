/*
 * filter.c - Packet filtering for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"


int itxtotal = 0;
int irxtotal = 0;

/*
 * Initialize the file descriptors for network monitoring sockets.
 */
void filter_setup()
{
    fwdfd = snoopfd = -1;
}

/*
 * Set up the idle filter mechanism for a connected link.
 */
void idle_filter_init()
{
    if (snoopfd != -1)
        close(snoopfd);
#ifdef HAVE_AF_PACKET
    if (af_packet && (snoopfd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0)
#endif
    {
	af_packet = 0;
	if ((snoopfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
	    mon_syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
	    die(1);
	}
    }

    if (fwdfd != -1)
	close(fwdfd);
#ifdef HAVE_AF_PACKET
    if (af_packet)
	fwdfd = socket(AF_PACKET, SOCK_DGRAM, 0);
    else
#endif
	fwdfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
    if (fwdfd < 0) {
        mon_syslog(LOG_ERR, "Could not get socket to do packet forwarding: %m");
        die(1);
    }

    if (current_mode == MODE_SLIP) {
	sprintf(snoop_dev,"sl%d",link_iface);
     } else if (current_mode == MODE_PPP) {
       sprintf(snoop_dev,"ppp%d",link_iface);
     } else if (current_mode == MODE_DEV) {
       sprintf(snoop_dev,"%s",current_dev);
      }
    if (debug) mon_syslog(LOG_DEBUG,"Changed snoop device to %s",snoop_dev);
    txtotal = rxtotal = 0;

#ifdef HAVE_AF_PACKET
    if (af_packet) {
	struct ifreq ifr;
	struct sockaddr_ll to;

	strncpy(ifr.ifr_name, snoop_dev, IFNAMSIZ);
	if (ioctl(snoopfd, SIOCGIFINDEX, &ifr) < 0)
	    mon_syslog(LOG_ERR, "ioctl SIOCGIFINDEX: %m");
	snoop_index = ifr.ifr_ifindex;
	memset(&to, 0, sizeof(to));
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = snoop_index;
	if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	    mon_syslog(LOG_ERR, "bind snoopfd: %m");
	bind(fwdfd, (struct sockaddr *)&to, sizeof(to));
    } else
#endif
    {
	struct sockaddr to;

	to.sa_family = AF_INET;
	strcpy(to.sa_data, snoop_dev);
	if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	    mon_syslog(LOG_ERR, "bind snoopfd: %m");
	bind(fwdfd, (struct sockaddr *)&to, sizeof(to));
    }
}

/*
 * Point the idle filter to proxy link.
 */
void idle_filter_proxy()
{
    if (fwdfd != -1) {
        if (debug) mon_syslog(LOG_DEBUG,"Closed fwdfd");
	close(fwdfd);
	fwdfd = -1;
    }

    if (snoopfd != -1)
        close(snoopfd);
#ifdef HAVE_AF_PACKET
    if (af_packet && (snoopfd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0)
#endif
    {
	af_packet = 0;
	if ((snoopfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
    	    mon_syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
    	    die(1);
	}
    }

    sprintf(snoop_dev,"%s%d", proxy_iftype, proxy_ifunit);
    if (debug) mon_syslog(LOG_DEBUG,"Changed snoop device to %s",snoop_dev);

#ifdef HAVE_AF_PACKET
    if (af_packet) {
	struct ifreq ifr;
	struct sockaddr_ll to;

	strncpy(ifr.ifr_name, snoop_dev, IFNAMSIZ);
	if (ioctl(snoopfd, SIOCGIFINDEX, &ifr) < 0)
	    mon_syslog(LOG_ERR, "ioctl SIOCGIFINDEX: %m");
	snoop_index = ifr.ifr_ifindex;
	memset(&to, 0, sizeof(to));
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = snoop_index;
	if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	    mon_syslog(LOG_ERR, "bind snoopfd: %m");
    } else
#endif
    {
	struct sockaddr to;

	to.sa_family = AF_INET;
	strcpy(to.sa_data, snoop_dev);
	if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	    mon_syslog(LOG_ERR, "bind snoopfd: %m");
    }
}

/*
 * We got a packet on the snooping socket.
 * Read the packet. Return 1 if the packet means the link should be up 0
 * otherwise. At the same time record the packet in the idle filter structure.
 */
void filter_read()
{
    union {
	struct sockaddr sa;
#ifdef HAVE_AF_PACKET
	struct sockaddr_ll sl;
#endif
    } from;
    size_t from_len = sizeof(from);
    int len;
    char packet[256];

    /* N.B. The packet buffer only needs to be big enough for the longest
     * header of any protocol we handle. Surplus data in a packet will
     * be silently discarded by the kernel. Letting it be copied to
     * user space is a waste of time and cache resources...
     */

    if ((len = recvfrom(snoopfd,packet,sizeof(packet),0,(struct sockaddr *)&from,&from_len)) > 0) {
	/* FIXME: really if the bind succeeds, then I don't need
	 * this check. How can I shortcut this effectly?
	 * perhaps two different filter_read routines?
         */
	if (
#ifdef HAVE_AF_PACKET
	(af_packet && from.sl.sll_ifindex != snoop_index)
	||
#endif
	(!af_packet && strcmp(from.sa.sa_data, snoop_dev) != 0))
	    return;

	/* For non AF_PACKET sockets we can only tell packets
	 * that are leaving our interface from this machine,
	 * forwarded packets all get counted as received bytes.
	 */
	if (
#ifdef HAVE_AF_PACKET
	(af_packet && from.sl.sll_pkttype == PACKET_OUTGOING)
	||
#endif
	(!af_packet && ((struct iphdr *)packet)->saddr == local_addr)) {
	    txtotal += len;
	    itxtotal += len;
	} else {
	    rxtotal += len;
	    irxtotal += len;
	}
	
	if ((ntohs(((struct iphdr *)packet)->frag_off) & 0x1fff) == 0) {
	    /* Mark passage of first packet */
	    if (check_firewall(fwunit,
		(af_packet ? (sockaddr_ll_t *)&from : NULL), packet, len)
	    && state == STATE_UP)
		state_timeout = -1;
	}
    }
}

void flush_timeout_queue()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_QFLUSH,&req);
}

void interface_up()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_UP,&req);
}

void interface_down()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_DOWN,&req);
}

int queue_empty()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_QCHECK,&req);
}

int fw_wait()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_WAIT,&req);
}

int fw_reset_wait()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_RESET_WAITING,&req);
}


void print_filter_queue(int sig)
{
    struct firewall_req req;
    mon_syslog(LOG_DEBUG,"User requested dump of firewall queue.");
    mon_syslog(LOG_DEBUG,"--------------------------------------");
    req.unit = fwunit;
    ctl_firewall(IP_FW_PCONN,&req);
    mon_syslog(LOG_DEBUG,"--------------------------------------");
}

void monitor_queue()
{
    char buf[100];
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_MCONN,&req);
    sprintf(buf,"LOAD\n%d\n%d\n",itxtotal,irxtotal);
    itxtotal = irxtotal = 0;
    mon_write(MONITOR_LOAD,buf,strlen(buf));
}
