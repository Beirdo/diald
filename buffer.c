/*
 * buffer.c - Packet buffering code.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * FIXME: This stuff should probably record the protocol that the
 * packet came in over so that we can use that info when forwarding
 * the packet. (It may not always be coming in over IP!)
 */

#include "diald.h"
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
	    for (i = 0; i < clen; i++)
		pkt[i] = B(head+6+i);
	    /* Subtle point here: normally we forward packets on the
	     *	"fwdfd" socket pointer. If we do this here, then
	     * the packet we foward will get seen by the filter again.
             * Since we've already seen these packets once, we don't
             * care to see them again. If instead we forward them
             * on the snoopfd (which points to the same device),
             * then we will never get them back on snoopfd.
             */
	    if (sendto(snoopfd, pkt, clen, 0, to, to_len) < 0) {
		mon_syslog(LOG_ERR,"Error forwarding data packet to physical device from buffer: %m");
	    }
	}
	head = (head+6+clen)%buffer_size;
	used -= (6+clen);
    }
}
