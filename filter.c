/*
 * filter.c - Packet filtering for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

extern char *current_dev;	/* From modem.c */

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
    struct ifreq ifr;
    struct sockaddr_ll to;

    if (snoopfd != -1)
        close(snoopfd);
    if ((snoopfd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
        die(1);
    }

    if (mode == MODE_SLIP) {
	sprintf(snoop_dev,"sl%d",link_iface);
     } else if (mode == MODE_PPP) {
       sprintf(snoop_dev,"ppp%d",link_iface);
     } else if (mode == MODE_DEV) {
       sprintf(snoop_dev,"%s",current_dev);
      }
    if (debug) syslog(LOG_INFO,"Changed snoop device to %s",snoop_dev);
    txtotal = rxtotal = 0;

    strncpy(ifr.ifr_name, snoop_dev, IFNAMSIZ);
    if (ioctl(snoopfd, SIOCGIFINDEX, &ifr) < 0)
	syslog(LOG_INFO, "ioctl SIOCGIFINDEX: %m");
    snoop_index = ifr.ifr_ifindex;
    memset(&to,0,sizeof(to));
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ALL);
    to.sll_ifindex = snoop_index;
    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	syslog(LOG_INFO, "bind snoopfd: %m");

    if (fwdfd != -1) {
	close(fwdfd);
    }
    if ((fwdfd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "Could not get socket to do packet forwarding: %m");
        die(1);
    }

    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    bind(fwdfd,(struct sockaddr *)&to,sizeof(to));
}

/*
 * Point the idle filter to proxy link.
 */
void idle_filter_proxy()
{
    struct ifreq ifr;
    struct sockaddr_ll to;

    if (fwdfd != -1) {
        if (debug) syslog(LOG_INFO,"Closed fwdfd");
	close(fwdfd);
	fwdfd = -1;
    }

    if (snoopfd != -1)
        close(snoopfd);
    if ((snoopfd = socket(AF_PACKET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
        die(1);
    }

    sprintf(snoop_dev,"sl%d",proxy_iface);
    if (debug) syslog(LOG_INFO,"Changed snoop device to %s",snoop_dev);

    /* try to bind the snooping socket to a particular device */
    /* Most likely this should close the old socket and open a new one first */
    strncpy(ifr.ifr_name, snoop_dev, IFNAMSIZ);
    if (ioctl(snoopfd, SIOCGIFINDEX, &ifr) < 0)
	syslog(LOG_INFO, "ioctl SIOCGIFINDEX: %m");
    snoop_index = ifr.ifr_ifindex;
    memset(&to,0,sizeof(to));
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ALL);
    to.sll_ifindex = snoop_index;

    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    if (bind(snoopfd, (struct sockaddr *)&to, sizeof(to)) < 0)
	syslog(LOG_INFO, "bind snoopfd: %m");
}

/*
 * We got a packet on the snooping socket.
 * Read the packet. Return 1 if the packet means the link should be up 0
 * otherwise. At the same time record the packet in the idle filter structure.
 */
void filter_read()
{
    struct sockaddr_ll from;
    size_t from_len = sizeof(struct sockaddr_ll);
    int len;

    if ((len = recvfrom(snoopfd,packet,4096,0,(struct sockaddr *)&from,&from_len)) > 0) {
	    if (do_reroute) {
		/* If we are doing unsafe routing, then we cannot count
		 * the transmitted packets on the forwarding side of the
		 * transitter (since there is none!), so we attempt to
		 * count them here.
		 */
		if (from.sll_pkttype == PACKET_OUTGOING) {
		    txtotal += len;
		    itxtotal += len;
		} else {
		    rxtotal += len;
		    irxtotal += len;
		}
	    } else {
	    	rxtotal += len;
		irxtotal += len;
	    }
	
            if ((ntohs(((struct iphdr *)packet)->frag_off) & 0x1fff) == 0) {
	        /* Mark passage of first packet */
	        if (check_firewall(fwunit,&from,packet,len) && state == STATE_UP)
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
    syslog(LOG_INFO,"User requested dump of firewall queue.");
    syslog(LOG_INFO,"--------------------------------------");
    req.unit = fwunit;
    ctl_firewall(IP_FW_PCONN,&req);
    syslog(LOG_INFO,"--------------------------------------");
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
