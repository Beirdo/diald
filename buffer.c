/*
 * buffer.c - Packet buffering code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>


#define B(i) buffer[(i)%buffer_size]

static int oldsize = 0;
static unsigned char *buffer = 0;
static int head = 0;
static int used = 0;
static int tail = 0;

void buffer_init(int *var, char **argv)
{
    buffer_size = atoi(*argv);
    if (buffer_size != oldsize) {
	if (buffer)
		free(buffer);
	buffer = malloc(buffer_size);
	oldsize = buffer_size;
    }
}

static void buffer_check()
{
    if (!buffer) {
	buffer = malloc(buffer_size);
	oldsize = buffer_size;
    }
}


void buffer_packet(unsigned int len,unsigned char *pkt)
{
    unsigned int clen;
    unsigned long stamp;
    unsigned long ctime = timestamp();

    buffer_check();
    if (len+6 > buffer_size) {
	mon_syslog(LOG_NOTICE,
	    "Can't buffer packet of length %d, buffer too small",
	    len);
	return;
    }
    if (buffer_fifo_dispose) {
	/* toss from the front of the buffer till we have space */
	while (used+len+6 > buffer_size) {
	    clen = (B(head)<<8) | B(head+1);
	    head = (head+6+clen)%buffer_size;
	    used -= (6+clen);
	}
    } else {
	for (;;) {
	    clen = (B(head)<<8) | B(head+1);
	    stamp = (B(head+2)<<24) | (B(head+3)<<16) | (B(head+4)<<8) | B(head+5);
	    if (stamp+buffer_timeout >= ctime)
		break;
	    head = (head+6+clen)%buffer_size;
	    used -= (6+clen);
	}
    }
    if (used+len+6 <= buffer_size) {
	used = used + 6 + len;
	B(tail) = (len>>8)&0xff;
	B(tail+1) = len&0xff;
	B(tail+2) = (ctime>>24)&0xff;
	B(tail+3) = (ctime>>16)&0xff;
	B(tail+4) = (ctime>>8)&0xff;
	B(tail+5) = ctime&0xff;
	tail = (tail+6)%buffer_size;
	while (len--) {
	    buffer[tail] = *pkt++;
	    tail = (tail+1)%buffer_size;
	}
    } else {
	mon_syslog(LOG_NOTICE,
	    "Can't buffer packet of length %d, only %d bytes available.",
	    len,buffer_size-(used+6));
    }
}

void forward_buffer()
{
    int forwarding = 0;
    unsigned int clen, i;
    unsigned long stamp;
    unsigned long ctime = timestamp();
    struct sockaddr_pkt sp;
#ifdef HAVE_AF_PACKET
    struct sockaddr_ll sl;
#endif
    struct sockaddr *to;
    size_t to_len;
    unsigned char pkt[4096];

#ifdef __linux__
    /* If we are using dynamic addresses we need to know whether we
     * are forwarding or not.
     */
    int d;
    if (dynamic_addrs
    && (d = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY)) >= 0) {
	char c;

	if (read(d, &c, 1) == 1 && c != '0')
	    forwarding = 1;
	close(d);
    }
#endif

    buffer_check();

#ifdef HAVE_AF_PACKET
    if (af_packet) {
	memset(&sl, 0, sizeof(sl));
	sl.sll_family = AF_PACKET;
	sl.sll_protocol = htons(ETH_P_IP);
	sl.sll_ifindex = snoop_index;
	to = (struct sockaddr *)&sl;
	to_len = sizeof(sl);
    } else
#endif
    {
	memset(&sp, 0, sizeof(sp));
	sp.spkt_family = AF_INET;
	strcpy(sp.spkt_device, snoop_dev);
	sp.spkt_protocol = htons(ETH_P_IP);
	to = (struct sockaddr *)&sp;
	to_len = sizeof(sp);
    }

    while (used > 0) {
	clen = (B(head)<<8) | B(head+1);
	stamp = (B(head+2)<<24) | (B(head+3)<<16) | (B(head+4)<<8) | B(head+5);
        if (stamp+buffer_timeout >= ctime) {
	    unsigned short wprot;
	    unsigned char *dpkt;
	    unsigned int dlen;

	    for (i = 0; i < clen; i++)
		pkt[i] = B(head+6+i);

	    wprot = *(unsigned short *)pkt;
	    dpkt = pkt + sizeof(unsigned short);
	    dlen = clen - sizeof(unsigned short);

	    /* If we are using dynamic addresses and forwarding traffic
	     * we send the packet back in to the kernel on the proxy so
	     * that it will go through the firewall/masquerading rules
	     * again. It is up to the user to enable and disable
	     * masquerading in ip-up/ip-down. Masquerading a packet
	     * which was incorrectly masqueraded to start with will
	     * never work :-).
	     * Note that if we push packets back to the kernel we
	     * probably lose the initial local traffic. If we send
	     * them directly we lose the initial masqueraded traffic.
	     */
	    if (dynamic_addrs && forwarding) {
		if (send_packet(wprot, dpkt, dlen) < 0)
		    mon_syslog(LOG_ERR,"Error bouncing packet to kernel from buffer: %m");
	    } else {
#ifdef HAVE_AF_PACKET
		if (af_packet)
		    sl.sll_protocol = wprot;
		else
#endif
		    sp.spkt_protocol = wprot;
		if (sendto(snoopfd, dpkt, dlen, 0, to, to_len) < 0)
		    mon_syslog(LOG_ERR,"Error forwarding data packet to physical device from buffer: %m");
	    }
	}
	head = (head+6+clen)%buffer_size;
	used -= (6+clen);
    }
}
