/*
 * firewall.c - Packet filtering for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * Copyright (c) 1999 Mike Jagdis.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <config.h>

#include <diald.h>


#if defined(__GLIBC__)
typedef u_int8_t __u8;
typedef u_int16_t __u16;
typedef u_int32_t __u32;
#endif

static FW_unit units[FW_NRUNIT];
static int initialized = 0;
int impulse_init_time = 0;
int impulse_time = 0;
int impulse_fuzz = 0;


void del_connection(FW_Connection *);
void zombie_connection(FW_Connection *);


static int
var_eval(FW_unit *unit, FW_ProtocolRule *pprule, struct var *v)
{
    unsigned char *hdr = pprule->hdr;
    unsigned char *data = pprule->data;
    unsigned char *n_p;

#if 0
mon_syslog(LOG_INFO, "    var 0x%08lx: valid %d, prule %d, type %d", v, v->valid, v->prule, v->type);
#endif
    /* If the var names a specific protocol header it must exist
     * in the current packet and the var value can be cached.
     * Unspecific var names are recalulated every time.
     */
    if ((v->valid & 2)) {
	pprule = &unit->prules[v->prule];
	if (!pprule->hdr)
	    return 0;
	if ((v->valid & 1))
	    return 1;
    }

    if (v->type == FW_VAR_STRING) {
#if 0
mon_syslog(LOG_DEBUG, "    var: prule %d: \"%s\"", v->prule, v->u.s);
#endif
    } else {
	int i, j;

	hdr = pprule->hdr;
	data = pprule->data;

	memset(v->u.n.value, 0, sizeof(v->u.n.value));
	if (v->u.n.width > 0) {
	    n_p = &(FW_IN_DATA(v->u.n.offset)?data:hdr)[FW_OFFSET(v->u.n.offset)];
	    /* Yes, it's a Duff's Device! */
	    i = FW_MAX_ADDR_UINTS-1-((v->u.n.width-1)/sizeof(v->u.n.value[0]));
	    switch (v->u.n.width % sizeof(v->u.n.value[0])) {
	    case 0: do {	v->u.n.value[i] = *(n_p++);
if (sizeof(v->u.n.value[0]) == 8) {
	    case 7:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    case 6:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    case 5:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    case 4:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
}
	    case 3:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    case 2:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    case 1:		v->u.n.value[i] = (v->u.n.value[i]<<8)|*(n_p++);
	    } while (++i < FW_MAX_ADDR_UINTS);
	    }
#if 0
mon_syslog(LOG_INFO, "got value: %08x:%08x:%08x:%08x", v->u.n.value[0], v->u.n.value[1], v->u.n.value[2], v->u.n.value[3]);
#endif

	    if (v->u.n.shift < 0) {
		j = 0;
		for (i=0; i<FW_MAX_ADDR_UINTS; i++) {
		    unsigned int bits = j;
		    j = v->u.n.value[i]
			<< (8*sizeof(v->u.n.value[0]) + v->u.n.shift);
		    v->u.n.value[i] = (v->u.n.value[i] >> -v->u.n.shift) | bits;
		}
	    } else if (v->u.n.shift > 0) {
		j = 0;
		for (i=FW_MAX_ADDR_UINTS-1; i>=0; i--) {
		    unsigned char bits = j;
		    j = v->u.n.value[i]
			>> (8*sizeof(v->u.n.value[0]) - v->u.n.shift);
		    v->u.n.value[i] = (v->u.n.value[i] << v->u.n.shift) | bits;
		}
	    }
#if 0
mon_syslog(LOG_INFO, "shifted: %08x:%08x:%08x:%08x", v->u.n.value[0], v->u.n.value[1], v->u.n.value[2], v->u.n.value[3]);
#endif
	}
	for (i=0; i<FW_MAX_ADDR_UINTS; i++)
	    v->u.n.value[i] = (v->u.n.value[i] & v->u.n.mask[i]);
#if 0
mon_syslog(LOG_INFO, "masked: %08x:%08x:%08x:%08x", v->u.n.value[0], v->u.n.value[1], v->u.n.value[2], v->u.n.value[3]);
#endif
	j = 0;
	for (i=FW_MAX_ADDR_UINTS-1; i>=0; i--) {
	    unsigned int old = v->u.n.value[i];
	    v->u.n.value[i] += v->u.n.cval[i] + j;
	    j = (v->u.n.value[i] < old) ? 1 : 0;
	}
#if 0
mon_syslog(LOG_INFO, "summed: %08x:%08x:%08x:%08x", v->u.n.value[0], v->u.n.value[1], v->u.n.value[2], v->u.n.value[3]);
#endif
#if 0
mon_syslog(LOG_DEBUG,"    var: prule %d: %s (0x%x[%d] << %d) & 0x%x + 0x%x = 0x%x",
	    v->prule,
	    FW_IN_DATA(v->u.n.offset) ? "data" : "hdr",
	    FW_HDR_OFFSET(v->u.n.offset),
	    v->u.n.width, v->u.n.shift,
	    v->u.n.mask[FW_MAX_ADDR_UINTS-1],
	    v->u.n.cval[FW_MAX_ADDR_UINTS-1],
	    v->u.n.value[FW_MAX_ADDR_UINTS-1]);
#endif
    }

    if (!(v->valid & 2))
	return 1;

    v->valid |= 1;
    v->next_dirty = pprule->var_dirty;
    pprule->var_dirty = v;
    return 1;
}


static void
var_format(char *buf, int bufsiz, char *fmt, struct var *var)
{
    if (var->type == FW_VAR_STRING) {
	snprintf(buf, bufsiz, fmt ? fmt : "%s", var->u.s);
    } else if (var->type == FW_VAR_PROTOCOL) {
	char *p, tbuf[16];
	unsigned int n = var->u.n.value[FW_MAX_ADDR_UINTS-1];
	p = getprotonumber(n);
	if (!p) {
	    sprintf(tbuf, "%u", n);
	    p = tbuf;
	}
	snprintf(buf, bufsiz, fmt ? fmt : "%s", p);
    } else if (var->type == FW_VAR_PORT) {
	char tbuf[16];
	unsigned int n = var->u.n.value[FW_MAX_ADDR_UINTS-1];
	sprintf(tbuf, "%u", n);
	snprintf(buf, bufsiz, fmt ? fmt : "%s", tbuf);
    } else if (var->type == FW_VAR_TCPPORT) {
	char *p, tbuf[16];
	unsigned int n = var->u.n.value[FW_MAX_ADDR_UINTS-1];
	p = NULL; /* getservicenumber("tcp", n); */
	if (!p) {
	    sprintf(tbuf, "%u", n);
	    p = tbuf;
	}
	snprintf(buf, bufsiz, fmt ? fmt : "%s", p);
    } else if (var->type == FW_VAR_UDPPORT) {
	char *p, tbuf[16];
	unsigned int n = var->u.n.value[FW_MAX_ADDR_UINTS-1];
	p = NULL; /* getservicenumber("udp", n); */
	if (!p) {
	    sprintf(tbuf, "%u", n);
	    p = tbuf;
	}
	snprintf(buf, bufsiz, fmt ? fmt : "%s", p);
    } else if (var->type == FW_VAR_DOTQUAD) {
	struct in_addr in;
	in.s_addr = htonl(var->u.n.value[FW_MAX_ADDR_UINTS-1]);
	snprintf(buf, bufsiz, fmt ? fmt : "%s", inet_ntoa(in));
    } else if (var->type == FW_VAR_INET6) {
	int i;
	unsigned int *w, words[FW_MAX_ADDR_BYTES/2];
	struct { int base, len; } best, curr;
	char *p, tmp[128];

	memset(words, 0, sizeof(words));
	for (w=words,i=0; i<FW_MAX_ADDR_UINTS; i++) {
	    if (sizeof(var->u.n.value[0]) == 8) {
		/* N.B. The shift values are 48 and 32 but we express
		 * them like this because otherwise the compiler gives
		 * warnings and the wannabe C gurus keep asking why
		 * they get compile "errors".
		 */
		*(w++) = (var->u.n.value[i]
			>> 8*3*(sizeof(var->u.n.value[0])/4)) & 0xffff;
		*(w++) = (var->u.n.value[i]
			>> 8*(sizeof(var->u.n.value[0])/2)) & 0xffff;
	    }
	    *(w++) = (var->u.n.value[i] >> 16) & 0xffff;
	    *(w++) = (var->u.n.value[i]) & 0xffff;
	}
	best.base = curr.base = -1;
	for (i=0; i<sizeof(words)/sizeof(words[0]); i++) {
	    if (words[i] == 0) {
		if (curr.base == -1)
		    curr.base = i, curr.len = 1;
		else
		    curr.len++;
	    } else if (curr.base != -1) {
		if (best.base == -1 || curr.len > best.len)
		    best = curr;
		curr.base = -1;
	    }
	}
	if (curr.base != -1
	&& (best.base == -1 || curr.len > best.len))
	    best = curr;
	if (best.base != -1 && best.len < 2)
	    best.base = -1;
	p = tmp;
	for (i=0; i<sizeof(words)/sizeof(words[0]); i++) {
	    if (best.base != -1 && i >= best.base && i < (best.base+best.len)) {
		if (i == best.base)
		    *(p++) = ':';
		continue;
	    }
	    if (i) *(p++) = ':';
	    if (i == 6 && best.base == 0
	    && (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
		struct in_addr in;
		in.s_addr = htonl(var->u.n.value[FW_MAX_ADDR_UINTS-1]);
		strcpy(p, inet_ntoa(in));
		break;
	    }
	    p += sprintf(p, "%x", words[i]);
	}
	if (best.base != -1
	&& (best.base + best.len == sizeof(words)/sizeof(words[0])))
	    *(p++) = ':';
	*p = '\0';
	snprintf(buf, bufsiz, fmt ? fmt : "%s", tmp);
    } else {
	int n = var->u.n.value[FW_MAX_ADDR_UINTS-1];
	/* FIXME: should print the other bytes in the value too. */
#if 1
	snprintf(buf, bufsiz, fmt ? fmt : "0x%x", n);
#else
	mon_syslog(LOG_WARNING, "Unknown var type %d", var->type);
	snprintf(buf, bufsiz, "0x%x", n);
#endif
    }
}


/*
 * Initialize the units.
 */

static void init_units(void)
{
    int i;

    memset(units,0,sizeof(units));
    for (i = 0; i < FW_NRUNIT; i++) {
	units[i].used = 0;
	units[i].filters = NULL;
	units[i].last = NULL;
	units[i].connections = malloc(sizeof(FW_Connection));
	units[i].nrules = 0;
	units[i].nfilters = 0;
	if (!units[i].connections) {
	    mon_syslog(LOG_ERR,"Out of memory! AIIEEE!");
	    die(1);
	}
	units[i].connections->next = units[i].connections->prev
	    = units[i].connections;
    }
    initialized = 1;
}

/* is the time given by "clock" in the given slot? */

static unsigned int in_slot(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime = ltime->tm_hour*60*60+ltime->tm_min*60+ltime->tm_sec; 

#if 0
    mon_syslog(LOG_DEBUG,"slot check: %d %d %d %d",
	ltime->tm_sec+ltime->tm_min*60+ltime->tm_hour*60*60, ltime->tm_wday,
	ltime->tm_mday, ltime->tm_mon);
#endif

    while (slot) {
#if 0
    mon_syslog(LOG_DEBUG,"slot def: %d %d %x %x %x",
	slot->start, slot->end, slot->wday, slot->mday, slot->month);
#endif 0
	if ((slot->start <= ctime)
	&&  (ctime <= slot->end)
	&&  (slot->wday & (1<<ltime->tm_wday))
	&&  (slot->mday & (1<<(ltime->tm_mday-1)))
	&&  (slot->month & (1<<ltime->tm_mon))) {
	    return 1;
	}
	slot = slot->next;
    }

    return 0;
}


/*
 * return 0 if the given time is in the given slots active time set.
 * Otherwise return the number of seconds until the slot is next active, or
 * the number of seconds until the next occurance of 00:00 hours, whichever
 * comes first.
 */

static unsigned int slot_start_timeout(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime, mintime;

    if (in_slot(slot,clock)) return 0;

    /* Ok, we are currently NOT in this slot's time range. */

    ctime = ltime->tm_hour*60*60 + ltime->tm_min*60 + ltime->tm_sec;
    mintime =  24*60*60 - ctime;

    while (slot) {
    	if ((slot->wday & (1<<ltime->tm_wday))
    	&& (slot->mday & (1<<(ltime->tm_mday-1)))
    	&& (slot->month & (1<<ltime->tm_mon))
	&& (slot->start >= ctime)) {
	    /* Ok, this slot disjunct occurs today */
	    if (mintime >= (slot->start - ctime))
		mintime = slot->start - ctime;
    	}
	slot = slot->next;
    }

    return mintime;
}

/*
 * return 0 if the given time is not in the given slots active time set.
 * Otherwise return the number of seconds until the slot times out, or
 * the number of seconds until the next occurance of 00:00 hours, whichever
 * comes first.
 */

static unsigned int slot_end_timeout(FW_Timeslot *slot, time_t *clock)
{
    struct tm *ltime = localtime(clock);
    int ctime, maxtime;

    if (!in_slot(slot,clock)) return 0;

    /* Ok, we are currently in this slot's time range. */

    ctime = ltime->tm_hour*60*60 + ltime->tm_min*60 + ltime->tm_sec;
    maxtime = -1;

    while (slot) {
    	if ((slot->wday & (1<<ltime->tm_wday))
    	&& (slot->mday & (1<<(ltime->tm_mday-1)))
    	&& (slot->month & (1<<ltime->tm_mon))
	&& (slot->start <= ctime)
	&& (ctime <= slot->end)) {
	    /* Ok, this slot disjunct is active now */
	    int t = slot->end - ctime;
	    if (maxtime <= t)
		maxtime = t;
    	}
	slot = slot->next;
    }

    if (maxtime == -1)
        return 24*60*60 - ctime;
    else
    	return maxtime;
}


/* Find a connection in the queue */
static FW_Connection *find_connection(FW_unit *unit, FW_ID *id)
{
    FW_Connection *c = unit->connections->next;

#if 0
{
int i;
for (i=0; i<id->nhdrs; i++)
mon_syslog(LOG_INFO, "got: %d: p=%d l=%d [ %02x %02x %02x %02x ]", i, id->hdr[i].proto, id->hdr[i].len, id->hdr[i].id[0], id->hdr[i].id[1], id->hdr[i].id[2], id->hdr[i].id[3]);
}
#endif
    /* look for a connection that matches this one */
    for (c = unit->connections->next; c != unit->connections; c = c->next) {
	int i;
#if 0
{
int i;
for (i=0; i<c->id.nhdrs; i++)
mon_syslog(LOG_INFO, "cmp: %d: p=%d l=%d [ %02x %02x %02x %02x ]", i, c->id.hdr[i].proto, c->id.hdr[i].len, c->id.hdr[i].id[0], c->id.hdr[i].id[1], c->id.hdr[i].id[2], c->id.hdr[i].id[3]);
}
#endif
	if (c->id.nhdrs != id->nhdrs)
	    continue;
	for (i=0; i<id->nhdrs; i++) {
	    if (c->id.hdr[i].prule != id->hdr[i].prule
	    || c->id.hdr[i].len != id->hdr[i].len
	    || memcmp(c->id.hdr[i].id, id->hdr[i].id, c->id.hdr[i].len))
		break;
	}
	if (i == id->nhdrs)
	    return c;
    }
    return 0;
}

/*
 * Add/update a connection in the queue.
 */

static void add_connection(FW_unit *unit, FW_Connection *c, FW_ID *id,
			unsigned int timeout, unsigned int conn_hold,
			TCP_STATE lflags,
			int direction, int len)
{
    /* look for a connection that matches this one */
    if (c == NULL) {
	    int d;
	    struct var **v;
	    char *p, *q;

	    /* no matching connection, add one */
	    c = malloc(sizeof(FW_Connection));
	    if (c == 0) {
	       mon_syslog(LOG_ERR,"Out of memory! AIIEEE!");
	       die(1);
	    }
	    p = c->description;
	    for (d=0; d<unit->ndescs; d++) {
		char **fmt;
		p = c->description;
		q = c->description + sizeof(c->description)-1;
		for (v=unit->descs[d].vars,fmt=unit->descs[d].fmt; *v; v++,fmt++) {
		    struct var *it = *v;
		    if (it->valid != 1
		    && !var_eval(unit, &unit->prules[0], it))
			break;
		    var_format(p, q-p, *fmt, it);
		    *q = '\0';
		    p += strlen(p);
#if 0
*p = '\0';
mon_syslog(LOG_INFO, "desc part: \"%s\"", c->description);
#endif
		}
		if (!*v) break;
	    }
	    *p = '\0';
	    c->desc_len = p - c->description;
#if 0
mon_syslog(LOG_INFO, "desc: len=%d, \"%s\"", c->desc_len, c->description);
#endif
	    c->id = *id;
	    c->packets[0] = c->packets[1] = 0;
	    c->bytes[0] = c->bytes[1] = 0;
	    c->bytes_total[0] = c->bytes_total[1] = 0;
	    c->packets[direction] = 1;
	    c->bytes[direction] = len;
            c->tcp_state = lflags;
	    c->unit = unit;
	    if (unit->live == 0 && timeout
	    && state != STATE_UP && !blocked && demand)
		mon_syslog(LOG_NOTICE, "Trigger: %s", c->description);

	    c->next = unit->connections->next;
	    c->prev = unit->connections;
	    unit->connections->next->prev = c;
	    unit->connections->next = c;

	    if (debug&DEBUG_CONNECTION_QUEUE)
    		mon_syslog(LOG_DEBUG,
		    "Adding connection %p @ %ld - timeout %d, conn hold %d",
		    c, time(0), timeout, conn_hold);
    } else {
	/* found a matching connection, toss it's old timer */
	    del_timer(&c->timer);
	    if (c->timer.function == (void *)zombie_connection)
		unit->live--;

	    c->packets[direction]++;
	    c->bytes[direction] += len;

	    if (debug&DEBUG_CONNECTION_QUEUE)
    		mon_syslog(LOG_DEBUG,
		    "Updating connection %p @ %ld - timeout %d",
		    c, time(0), timeout);
    }

    c->conn_hold = conn_hold;
    init_timer(&c->timer);
    c->timer.data = (void *)c;
    if (timeout) {
	c->timer.expires = timeout;
	c->timer.function = (void *)zombie_connection;
	unit->live++;
	goto out;
    }

    c->timer.function = (void *)del_connection;
    c->timer.expires = conn_hold;
out:
    add_timer(&c->timer);
}


/*
 * Get a connection out of a queue.
 */

void del_connection(FW_Connection *c)
{
    if (debug&DEBUG_CONNECTION_QUEUE)
	mon_syslog(LOG_DEBUG,"Deleting connection %p @ %ld",c,time(0));

    c->next->prev = c->prev;
    c->prev->next = c->next;
    free(c);
}

void zombie_connection(FW_Connection *c)
{
    if (debug&DEBUG_CONNECTION_QUEUE)
	mon_syslog(LOG_DEBUG,"Connection zombie %p @ %ld",c,time(0));

    if (!c->conn_hold) {
	del_connection(c);
	goto out;
    }

    c->timer.function = (void *)del_connection;
    c->timer.expires = c->conn_hold;
    add_timer(&c->timer);
out:
}

void del_impulse(FW_unit *unit)
{

    if (unit->impulse_mode) {
	unit->impulse_mode = 0;
	if (impulse_time > 0) {
	    unit->impulse.data = (void *)unit;
	    unit->impulse.function = (void *)(void *)del_impulse;
	    unit->impulse.expires = impulse_time;
	    if (debug&DEBUG_CONNECTION_QUEUE)
		mon_syslog(LOG_DEBUG,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
	    add_timer(&unit->impulse);
	}
    } else {
	unit->impulse_mode = 1;
	impulse_init_time = 0;	/* zero the initial impulse time */
	if (impulse_fuzz > 0) {
	    unit->impulse.data = (void *)unit;
	    unit->impulse.function = (void *)(void *)del_impulse;
	    unit->impulse.expires = impulse_fuzz;
	    if (debug&DEBUG_CONNECTION_QUEUE)
		mon_syslog(LOG_DEBUG,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
	    add_timer(&unit->impulse);
	}
    }
}

/* Check if a forcing rule currently applies to the connection */

static void fw_force_update(FW_unit *unit)
{
    FW_Filters *fw;
    int timeout, mintime;
    time_t clock = time(0);

    /* check if the current forcing slot has expired */
    if (unit->force_etime > clock) return;

    fw = unit->filters;
    mintime = 24*60*60;
    unit->force = 0;

    while (fw) {
	if (fw->filt.type == FW_TYPE_UP || fw->filt.type == FW_TYPE_DOWN) {
	    /* check when the rule is next applicable */
	    timeout = slot_start_timeout(fw->filt.times,&clock);
	
	    if (timeout > 0) {
		/* first time at which a previous slot starts */
		if (timeout < mintime)
		    mintime = timeout;
		goto next_rule;
	    } else {
		/* time at which the current slot ends */
		timeout = slot_end_timeout(fw->filt.times,&clock);
		if (timeout < mintime)
		    mintime = timeout;
	    }
	} else
	    goto next_rule;

        if (fw->filt.type == FW_TYPE_UP)
	    unit->force = 1;
	else
	    unit->force = 2;

	break;

next_rule: /* try the next filter */
	fw = fw->next;
    }

    unit->force_etime = clock + mintime;
}

/* Check if an impulse rule currently applies to the connection */

static void fw_impulse_update(FW_unit *unit, int force)
{
    FW_Filters *fw;
    int timeout, mintime, itimeout, ifuzz, ftimeout;
    time_t clock = time(0);

    /* check if the current forcing slot has expired */
    if (clock < unit->impulse_etime && !force) return;

    fw = unit->filters;
    mintime = 24*60*60;
    itimeout = 0;
    ftimeout = 0;
    ifuzz = 0;

    while (fw) {
	if (fw->filt.type == FW_TYPE_IMPULSE) {
	    /* check when the rule is next applicable */
	    timeout = slot_start_timeout(fw->filt.times,&clock);
	    if (timeout > 0) {
		/* Will be applicable soon */
		/* first time at which a previous slot starts
	 	 * (i.e. schedule changes) */
		if (timeout < mintime)
		    mintime = timeout;
		goto next_rule;
	    } else {
		/* time at which the current slot ends */
		timeout = slot_end_timeout(fw->filt.times,&clock);
		ifuzz = fw->filt.fuzz;
		itimeout = fw->filt.timeout;
		if (timeout < itimeout)	/* chop impulse at change boundary */
		    itimeout = timeout;
		ftimeout = fw->filt.timeout2;
		if (timeout < itimeout)	/* chop impulse at change boundary */
		    ftimeout = timeout;
		if (timeout < mintime)
		    mintime = timeout;
	    }
	} else
	    goto next_rule;

	break;

next_rule: /* try the next filter */
	fw = fw->next;
    }
    unit->impulse_etime = clock + mintime;

    del_timer(&unit->impulse);
    if (unit->up && (itimeout > 0 || (force && ftimeout > 0))) {
    	/* place the current impulse generator into the impulse queue */
    	impulse_time = itimeout;
   	impulse_init_time = ftimeout;
    	impulse_fuzz = ifuzz;
    	unit->impulse_mode = 0;
    	unit->impulse.data = (void *)unit;
    	unit->impulse.function = (void *)(void *)del_impulse;
    	unit->impulse.expires = (force)?ftimeout:itimeout;
    	add_timer(&unit->impulse);
	if (debug&DEBUG_CONNECTION_QUEUE)
	    mon_syslog(LOG_DEBUG,"Refreshing impulse generator: mode %d, time %ld @ %ld",unit->impulse_mode,unit->impulse.expires,time(0));
    } else {
	/* set these so that the monitor output is sane */
	unit->impulse_mode = 1;
	impulse_init_time = 0;
    }
}

static void log_packet(int accept, struct iphdr *pkt, int len,  int rule)
{
    char saddr[20], daddr[20];
    struct in_addr addr;
    int sport = 0, dport = 0;
    struct tcphdr *tcp = (struct tcphdr *)((char *)pkt + 4*pkt->ihl);
    struct udphdr *udp = (struct udphdr *)tcp;

    addr.s_addr = pkt->saddr;
    strcpy(saddr,inet_ntoa(addr));
    addr.s_addr = pkt->daddr;
    strcpy(daddr,inet_ntoa(addr));

    if (pkt->protocol == IPPROTO_TCP || pkt->protocol == IPPROTO_UDP)
	sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if (pkt->protocol == IPPROTO_TCP) {
	mon_syslog(LOG_DEBUG,
	    "filter %s rule %d proto tcp len %d seq %lx ack %lx flags %s%s%s%s%s%s packet %s,%d => %s,%d",
	    (accept)?"accepted":"ignored",
	    rule,
	    ntohs(pkt->tot_len),
	    ntohl(tcp->seq), ntohl(tcp->ack_seq),
	    (tcp->fin) ? " FIN" : "",
	    (tcp->syn) ? " SYN" : "",
	    (tcp->rst) ? " RST" : "",
	    (tcp->psh) ? " PUSH" : "",
	    (tcp->ack) ? " ACK" : "",
	    (tcp->urg) ? " URG" : "",
	    saddr, sport, daddr, dport);
    } else {
	mon_syslog(LOG_DEBUG,
	    "filter %s rule %d proto %s len %d packet %s,%d => %s,%d",
	    (accept)?"accepted":"ignored",
	    rule,
	    getprotonumber(pkt->protocol),
	    htons(pkt->tot_len),
	    saddr, sport, daddr, dport);
    }
}


void print_filter(FW_Filter *filter)
{
    int i;
    mon_syslog(LOG_DEBUG,"filter: prl %d log %d type %d cnt %d tm %d",
	filter->prule,filter->log,filter->type,
	filter->count,filter->timeout);
    for (i = 0; i < filter->count; i++) {
	mon_syslog(LOG_DEBUG,"    term: %s (%d[%d] << %d) & %x op<%d> %x",
	    FW_IN_DATA(filter->terms[i].var->u.n.offset) ? "data" : "hdr",
	    FW_HDR_OFFSET(filter->terms[i].var->u.n.offset),
	    filter->terms[i].var->u.n.width,
	    filter->terms[i].var->u.n.shift,
	    filter->terms[i].var->u.n.mask[FW_MAX_ADDR_UINTS-1]
		& (filter->terms[i].mask
		    ? filter->terms[i].mask->u.n.value[FW_MAX_ADDR_UINTS-1] : (~0)),
	    filter->terms[i].op,
	    filter->terms[i].test ? filter->terms[i].test->u.n.value[FW_MAX_ADDR_UINTS-1] : 0);
    }
}

__u16 checksum(__u16 *buf, int nwords)
{
   unsigned long sum;

   /* WARNING: possible endianess assumptions here! */
   for (sum = 0; nwords > 0; nwords--)
      sum += *buf++;
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return ~sum ;
}


void forge_tcp_reset(unsigned short wprot, struct iphdr *iph, int len)
{
    struct tcphdr *tcph,*ntcph;
    struct iphdr *niph;
    struct pseudo {
	__u32 saddr;
	__u32 daddr;
	__u8  zero;
	__u8  ptcl;
	__u16 len;
    } *pseudo;

    tcph = (struct tcphdr *)((char *)iph + 4*iph->ihl);

    if (iph == 0 || iph->frag_off&htons(0x1fff) || tcph->rst)
	return;

    niph = malloc(sizeof(struct tcphdr)+sizeof(struct iphdr)
		+sizeof(struct pseudo));
    if (niph == 0) return;

    niph->ihl = 5;	/* Header length in octets. */
    niph->tot_len = htons(sizeof(struct tcphdr)+sizeof(struct iphdr));
    niph->version = 4;
    niph->tos = (iph->tos & 0x1E) | 0xC0;
    niph->id = iph->id;
    niph->frag_off = 0;
    niph->ttl = 16;
    niph->protocol = IPPROTO_TCP;
    niph->saddr = iph->daddr; /* We may be lying. Shrugh. */
    niph->daddr = iph->saddr; /* Were we sent the reject message */
    niph->check = 0;
    niph->check = checksum((__u16 *)niph, sizeof(struct iphdr)>>1);

    /* We should also be copying the ip options at this point.
     * (More major barf bag material.)
     */

    ntcph = (struct tcphdr *)((char *)niph + sizeof(struct iphdr));

    ntcph->source = tcph->dest;
    ntcph->dest = tcph->source;
    ntcph->res1 = 0;
    ntcph->res2 = 0;
    ntcph->doff = sizeof(struct tcphdr)/4;
    ntcph->fin = 0;
    ntcph->syn = 0;
    ntcph->rst = 1;
    ntcph->psh = 0;
    ntcph->urg = 0;
    ntcph->window = 0;
    ntcph->urg_ptr = 0;
    if (tcph->ack) {
	    ntcph->ack = 0;
	    ntcph->seq = tcph->ack_seq;
	    ntcph->ack_seq = 0;
    } else {
	    ntcph->ack = 1;
	    ntcph->seq = 0;
	    if (!tcph->syn)
		    ntcph->ack_seq = tcph->seq;
	    else
		    ntcph->ack_seq = htonl(ntohl(tcph->seq)+1);
    }
    pseudo = (struct pseudo*)(ntcph + 1);
    pseudo->saddr = niph->saddr;
    pseudo->daddr = niph->daddr;
    pseudo->zero = 0;
    pseudo->ptcl = niph->protocol;
    pseudo->len = ntohs(sizeof(struct tcphdr));
    ntcph->check = 0;
    ntcph->check = checksum((__u16 *)ntcph,(sizeof(struct tcphdr)+sizeof(struct pseudo))>>1);

    /*
     * OK, send the packet now.
     */
    send_packet(wprot, (unsigned char *)niph,
	sizeof(struct tcphdr)+sizeof(struct iphdr));

    free((void *)niph);
}


/* Check if a packet passes the filters */
static int
check_packet(FW_unit *unit, FW_ID *id,
    sockaddr_ll_t *sll, unsigned char direction, unsigned char *pkt, int len,
    FW_ProtocolRule *tcp_prule)
{
    FW_Filters *fw;
    FW_ProtocolRule *pprule;
    int i;
    FW_Term *term;
    int rule;
    int opdir;
#if 1 /* TCP KLUDGE */
    TCP_STATE lflags;
#endif
    clock_t clock = time(0);
    FW_Connection *conn;
    struct iphdr * ip_pkt = (struct iphdr *)pkt;

    /* Now swap the source and dest id elements for packets
     * going out so we see one connection regardless of packet
     * direction.
     */
#if 0
for (i=0; i<id->nhdrs; i++) {
int j;
char *p, buf[256];
p = buf + sprintf(buf, "A %d: proto %d, len %d,", i, unit->prules[id->hdr[i].prule].protocol, id->hdr[i].len);
for (j=0; j<id->hdr[i].len; j++)
    p += sprintf(p, " %02x", id->hdr[i].id[j]);
mon_syslog(LOG_INFO, buf);
}
#endif
    if (direction == 1) {
	for (i=0; i<id->nhdrs; i++) {
	    FW_ProtocolRule *idp = &unit->prules[id->hdr[i].prule];
	    int s, d;
	    s = d = 0;
	    while (s<id->hdr[i].len && d<id->hdr[i].len) {
		unsigned char t;
		while (s<id->hdr[i].len && !FW_IN_SRC(idp->codes[s])) s++;
		while (d<id->hdr[i].len && !FW_IN_DST(idp->codes[d])) d++;
		t = id->hdr[i].id[s];
		id->hdr[i].id[s] = id->hdr[i].id[d];
		id->hdr[i].id[d] = t;
		s++, d++;
	    }
	}
    }
#if 0
for (i=0; i<id->nhdrs; i++) {
int j;
char *p, buf[256];
p = buf + sprintf(buf, "B %d: proto %d, len %d,", i, unit->prules[id->hdr[i].prule].protocol, id->hdr[i].len);
for (j=0; j<id->hdr[i].len; j++)
    p += sprintf(p, " %02x", id->hdr[i].id[j]);
mon_syslog(LOG_INFO, buf);
}
#endif

    conn = find_connection(unit, id);
    opdir = (direction==1)?2:1;


#if 1 /* TCP KLUDGE */
    /* FIXME: how do I get this out of here? */
    /* Do the TCP liveness changes */
    memset(&lflags, 0, sizeof(lflags));
    if (tcp_prule) {
	struct tcphdr *tcp = (struct tcphdr *)tcp_prule->hdr;
	int tcp_data_len = ntohs(ip_pkt->tot_len) - (4*ip_pkt->ihl + tcp->doff*4);

	if (conn) {
	    lflags = conn->tcp_state;
	} else {
	    lflags.fin_seq[0] = lflags.fin_seq[1] = 0;
	    lflags.tcp_flags = 0;
            lflags.saw_fin = 0;
	}
	if (tcp->rst) {
	    lflags.saw_fin = 0;
	    lflags.tcp_flags = 0;
	} else if (tcp->fin) {
	    lflags.saw_fin |= direction;
	    lflags.fin_seq[direction-1] = ntohl(tcp->seq)+tcp_data_len+1;
	} else if (tcp->syn || tcp_data_len > 0) {
	    /* Either we have a SYN packet, or we have a data carrying
   	     * packet. In either case we want to declare this direction live.
	     * FIXME. It is possible that this should set saw_fin to 0 in the
	     * case that we have a SYN packet.
	     */
	    lflags.saw_fin &= ~direction;
	    lflags.tcp_flags |= direction;
	}
	if ((lflags.saw_fin & opdir) && (tcp->ack)) {
	    if (lflags.fin_seq[opdir-1] <= ntohl(tcp->ack_seq)) {
		lflags.tcp_flags &= ~direction;
	    }
	}

	if (conn) {
	    conn->tcp_state = lflags;
	}
    }
#endif

    rule = 1;
    fw = unit->filters;
    while (fw) {
#if 0
	print_filter(&fw->filt);
#endif
	/* is this rule currently applicable? */
	if ((unit->up && fw->filt.type == FW_TYPE_BRINGUP)
	   || (!unit->up && fw->filt.type == FW_TYPE_KEEPUP)
	   || !in_slot(fw->filt.times,&clock)
	   || fw->filt.type == FW_TYPE_IMPULSE
	   || fw->filt.type == FW_TYPE_UP
	   || fw->filt.type == FW_TYPE_DOWN)
	    goto next_rule;

	/* Check the protocol rule for this filter is active */
	pprule = &unit->prules[fw->filt.prule];
	if (pprule->hdr == NULL)
	    goto next_rule;

	/* Check the terms */
	for (i = 0;
	(fw->filt.count > FW_MAX_TERMS) || (i < fw->filt.count); i++) {
	    static unsigned int vzero[FW_MAX_ADDR_UINTS] = { 0, };
	    unsigned int v[FW_MAX_ADDR_UINTS];
	    unsigned int *vref;
	    int j;

	    if (i > FW_MAX_TERMS && fw->filt.count == 0) {
		fw = fw->next, i = 0;
		if (fw == NULL) break;
	    }
	    term = &fw->filt.terms[i];
#if 0
mon_syslog(LOG_INFO, "check var %s", term->var->name ? term->var->name : "???");
#endif
#if 1 /* TCP KLUDGE */
	    if (FW_TCP_STATE(term->var->u.n.offset)) {
#if 0
		v = (lflags.tcp_flags >> term->var->shift) && term->mask;
#endif
		memset(v, 0, sizeof(v));
		v[FW_MAX_ADDR_UINTS-1] = lflags.tcp_flags;
	    } else {
#endif
	    /* vars with no specified prule look at the entire packet.
	     * vars with a prule override whatever we pass as the default.
	     */
	    if (term->var->valid != 1
	    && !var_eval(unit, &unit->prules[0], term->var))
		goto next_rule;
	    memcpy(v, term->var->u.n.value, sizeof(v));
#if 1 /* TCP KLUDGE */
	    }
#endif

#if 0
mon_syslog(LOG_INFO, "cmp 0x%x & 0x%x op=%d 0x%x", v[FW_MAX_ADDR_UINTS-1], term->mask ? term->mask->u.n.value[FW_MAX_ADDR_UINTS-1] : (~0), term->op, term->test ? term->test->u.n.value[FW_MAX_ADDR_UINTS-1] : 0);
#endif
	    if (term->mask) {
		int i;
		if (term->mask->valid != 1
		&& !var_eval(unit, &unit->prules[0], term->mask))
		    goto next_rule;
		for (i=0; i<FW_MAX_ADDR_UINTS; i++)
		    v[i] &= term->mask->u.n.value[i];
	    }

	    if (term->test
	    && term->test->valid != 1
	    && !var_eval(unit, &unit->prules[0], term->test))
		goto next_rule;

	    vref = (term->test ? term->test->u.n.value : vzero);

	    switch (term->op) {
	    case FW_EQ:
		for (j=FW_MAX_ADDR_UINTS-1; j>=0; j--)
		    if (v[j] != vref[j])
			goto next_rule;
		break;
	    case FW_NE:
#if 0
mon_syslog(LOG_INFO, "cmp 0x%x & 0x%x op=%d 0x%x", v[FW_MAX_ADDR_UINTS-1], term->mask ? term->mask->u.n.value[FW_MAX_ADDR_UINTS-1] : (~0), term->op, vref[FW_MAX_ADDR_UINTS-1]);
#endif
		for (j=FW_MAX_ADDR_UINTS-1; j>=0; j--) {
		    if (v[j] != vref[j])
			break;
		}
		if (j < 0) goto next_rule;
		break;
	    case FW_GE:
		for (j=0; j<FW_MAX_ADDR_UINTS; j++)
		    if (v[j] < vref[j])
			    goto next_rule;
		break;
	    case FW_LE:
		for (j=0; j<FW_MAX_ADDR_UINTS; j++)
		    if (v[j] > vref[j])
			    goto next_rule;
		break;
	    }
	}
	/* Ok, we matched a rule. What are we suppose to do? */
#if 0
	if (fw->filt.log)
#endif
#if 1
	/* FIXME: need to pass id headers */
        if (debug&DEBUG_FILTER_MATCH)
#endif
	    log_packet(fw->filt.type!=FW_TYPE_IGNORE,ip_pkt,len,rule);

	/* Check if this entry goes into the queue or not */
	if (conn || fw->filt.timeout || fw->filt.conn_hold) {
	    add_connection(
		unit,
		conn,
		id,
		fw->filt.timeout,
		fw->filt.conn_hold,
		lflags,
		direction-1,
		len);
	}
	/* check if we are no longer waiting */
	if (fw->filt.type == FW_TYPE_WAIT) {
		unit->waiting = 0;
		/* WAITING rules don't do the final match, but
		 * must occur before other rules
		 */
		goto next_rule;
	}

	/* Return 1 if accepting rule with non zero timeout, 0 otherwise */
	return (fw->filt.type != FW_TYPE_IGNORE && fw->filt.type != FW_TYPE_WAIT && fw->filt.timeout > 0);

next_rule: /* try the next filter */
	fw = fw->next;
	rule++;
    }

skip:
    /* Failed to match any rule. This means we ignore the packet */
    /* FIXME: need to pass id headers */
    if (debug&DEBUG_FILTER_MATCH)
        log_packet(0,ip_pkt,len,0);
    return 0;
}


int
check_firewall(int unitnum, sockaddr_ll_t *sll, unsigned char *pkt, int len)
{
    FW_unit *unit;
    unsigned char *plist;
    FW_ProtocolRule *pprule;
    FW_ID id;
    unsigned short proto;
    struct var *v;
    int i, n;
#if 1 /* TCP KLUDGE */
    FW_ProtocolRule *tcp_prule = NULL;
#endif
    unsigned char *data;
    unsigned char direction;

    if (!initialized) init_units();

    if (unitnum < 0 || unitnum >= FW_NRUNIT) {
	/* FIXME: set an errorno? */
	return -1;
    }

    unit = &units[unitnum];

#if 0 /* XXXXX */
     /* If we have the "strict-forwarding" option set then unless one of
     * the two addresses matches the local address we should ignore it.
     */
    if (strict_forwarding
    && (!sll || sll->sll_protocol == htons(ETH_P_IP))
    && ip_pkt->saddr != local_addr && ip_pkt->daddr != local_addr) {
	/* We forge resets for TCP protocol stuff that has been
	 * shut down do to a link failure.
	 */
	if (ip_pkt->protocol == IPPROTO_TCP)
	    forge_tcp_reset(htons(ETH_P_IP), ip_pkt, len);
	
	goto skip;
    }
#endif

    /* Flush any old header data. (We stomp prule 0 anyway below...) */
    i = unit->prules[0].next_dirty;
    while (i) {
	int j = i;
	unit->prules[j].hdr = unit->prules[j].data = NULL;
	unit->prules[j].next_dirty = 0;
	i = unit->prules[j].next_dirty;
    }
    unit->prules[0].next_dirty = 0;

    /* Invalidate all vars associated with prule 0. */
    for (v = unit->prules[0].var_dirty; v; v = v->next_dirty)
	v->valid &= 2;
    unit->prules[0].var_dirty = NULL;
    unit->prules[0].hdr = pkt;
    unit->prules[0].data = pkt;

    /* Find the protocol headers */
    proto = (sll ? ntohs(sll->sll_protocol) : ETH_P_IP);
    data = pkt;
    id.nhdrs = 0;
    plist = unit->prules[0].sub;
    n = unit->prules[0].nsubs;
    /* FIXME: watch for packet/header overruns */
    for (i = 0; i < n; i++) {
	pprule = &unit->prules[plist[i]];
#if 0
mon_syslog(LOG_INFO, "    proto 0x%x, rule 0x%x", proto, pprule->protocol);
#endif
	if (FW_PROTO_ALL(pprule->protocol)
	|| pprule->protocol == proto) {
	    unsigned char *hdr = data;
	    int j;

	    /* Invalidate all vars associated with this prule. */
	    for (v = pprule->var_dirty; v; v = v->next_dirty)
		v->valid &= 2;
	    pprule->var_dirty = NULL;

	    pprule->hdr = hdr;
	    pprule->data = data;
	    if (!pprule->next_dirty) {
		pprule->next_dirty = unit->prules[0].next_dirty;
		unit->prules[0].next_dirty = plist[i];
	    }

	    if (pprule->nxt_offset) {
	        if (pprule->nxt_offset->valid == 1
		|| var_eval(unit, pprule, pprule->nxt_offset)) {
		    data += pprule->nxt_offset->u.n.value[FW_MAX_ADDR_UINTS-1];
		    pprule->data = data;
		}
	    }

#if 0
mon_syslog(LOG_INFO, "prule %d, proto 0x%x  hdr 0x%08lx  data 0x%08lx", plist[i], proto, hdr, data);
#endif

	    /* FIXME: all headers are considered significant here
	     * but if we have a tunnel with connections through it
	     * and then tear it down and go direct the connections
	     * are still the same even though we are a header less.
	     */
	    if (pprule->clen > 0) {
		id.hdr[id.nhdrs].prule = plist[i];
		id.hdr[id.nhdrs].len = pprule->clen;
		for (j = 0; j < pprule->clen; j++)
		    id.hdr[id.nhdrs].id[j] =
			(FW_IN_DATA(pprule->codes[j]) ? data : hdr)
				[FW_OFFSET(pprule->codes[j])];
		id.nhdrs++;
	    }

#if 1 /* TCP KLUDGE */
	    if (proto == IPPROTO_TCP)
		tcp_prule = pprule;
#endif

	    if (!pprule->nxt_proto)
		break;
	    if (pprule->nxt_proto->valid != 1
	    && !var_eval(unit, pprule, pprule->nxt_proto))
		break;
	    proto = pprule->nxt_proto->u.n.value[FW_MAX_ADDR_UINTS-1];
	    plist = pprule->sub;
	    n = pprule->nsubs;
	    i = -1;
	}
    }

    if (data == pkt)
	return -1;	/* No protocol rules? */

#ifdef HAVE_AF_PACKET
    if (sll) {
	direction = 1;
	if (sll->sll_pkttype != PACKET_OUTGOING)
	    direction = 2;
    } else
#endif
    {
	direction = 0;
	for (i=0; !direction && i<id.nhdrs; i++) {
	    FW_ProtocolRule *idp = &unit->prules[id.hdr[i].prule];
	    int s, d;
	    s = d = 0;
	    while (!direction && s<id.hdr[i].len && d<id.hdr[i].len) {
		while (s<id.hdr[i].len && !FW_IN_SRC(idp->codes[s])) s++;
		while (d<id.hdr[i].len && !FW_IN_DST(idp->codes[d])) d++;
		if (s<id.hdr[i].len && d<id.hdr[i].len) {
		    if (id.hdr[i].id[s] < id.hdr[i].id[d])
			direction = 1;
		    else if (id.hdr[i].id[s] < id.hdr[i].id[d])
			direction = 2;
		}
		s++, d++;
	    }
	}
    }

    /* The outermost packet header is a single byte giving the
     * direction the packet is travelling (1=in, 2=out). The
     * outermost packet data is the entire packet as received.
     */
    unit->prules[0].hdr = &direction;
    unit->prules[0].data = pkt;

    return check_packet(unit, &id, sll, direction, pkt, len, tcp_prule);
}

static char * pcountdown(char *buf, long secs)
{
    /* Make sure that we don't try to print values that overflow our buffer */
    if (secs < 0) secs = 0;
    if (secs > 359999) secs = 359999;
    sprintf(buf,"%02ld:%02ld:%02ld",secs/3600,(secs/60)%60,secs%60);
    return buf;
}

int ctl_firewall(int op, struct firewall_req *req)
{
    FW_unit *unit;
    if (!initialized) init_units();

    /* Need to check that req is OK */

    if (req && req->unit >= FW_NRUNIT) return -1; /* ERRNO */

    if (req) unit = &units[req->unit];
    else unit = units;
    
    switch (op) {
    case IP_FW_QFLUSH:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Connection *c,*cn;
	    for (c = unit->connections->next;
	    c != unit->connections; c = cn) {
		cn = c->next;
		del_timer(&c->timer);
		del_connection(c);
	    }
	    return 0;
	}
    case IP_FW_QCHECK:
	if (!req) return -1; /* ERRNO */
	
	fw_force_update(unit);
	fw_impulse_update(unit,0);

	return (unit->force == 2
		|| (unit->force == 0
		    && !(unit->up && unit->impulse_mode == 0
		   	 && (impulse_init_time > 0 || impulse_time > 0))
		    && unit->live == 0));


    /* FIXME: we do not appear to actually free things properly... */
    case IP_FW_PFLUSH:
	if (!req) return -1; /* ERRNO */
	unit->nrules = 0;
	return 0;
    /* PFLUSH implies FFLUSH */
    case IP_FW_FFLUSH:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Filters *next, *filt = unit->filters;
	    while (filt)
	    	{ next = filt->next; free(filt); filt = next; }
	    unit->filters = NULL;
	    unit->last = NULL;
	}
	return 0;
    case IP_FW_AFILT:
	if (!req) return -1; /* ERRNO */
	{
	    FW_Filters *filters = malloc(sizeof(FW_Filters));
	    if (filters == 0) {
		mon_syslog(LOG_ERR,"Out of memory! AIIEEE!");
		return -1; /* ERRNO */
	    }
	    filters->next = 0;
	    filters->filt = req->fw_arg.filter;
	    if (unit->last) unit->last->next = filters;
	    if (!unit->filters) unit->filters = filters;
	    unit->last = filters;
	    unit->nfilters++;
	}
	return 0;
    case IP_FW_APRULE:
	if (!req) return -1; /* ERRNO */
	if (unit->nrules >= FW_MAX_PRULES) return -1; /* ERRNO */
	unit->prules[(int)unit->nrules] = req->fw_arg.rule;
	return unit->nrules++;
    case IP_FW_ADESC:
	if (!req) return -1; /* ERRNO */
	if (unit->ndescs >= FW_MAX_DESCS) return -1; /* ERRNO */
	unit->descs[(int)unit->ndescs] = req->fw_arg.desc;
	return unit->ndescs++;
    case IP_FW_APSUB: {
	int n;
	FW_ProtocolRule *prule;
	if (!req) return -1; /* ERRNO */
	n = req->fw_arg.vals[0];
	if (n >= unit->nrules) return -1;
	prule = &unit->prules[n];
	if (prule->nsubs >= FW_MAX_PRULES) return -1; /* ERRNO */
	prule->sub[(int)prule->nsubs] = req->fw_arg.vals[1];
	return prule->nsubs++;
    }
    /* Printing does nothing right now */
    case IP_FW_PCONN:
	if (!req) return -1; /* ERRNO */
	{
	    unsigned long atime = time(0);
            unsigned long tstamp = timestamp();
	    FW_Connection *c;
	    char saddr[20], daddr[20];
    	    struct in_addr addr;
	    mon_syslog(LOG_DEBUG,"up = %d, forcing = %d, impulse = %d, iitime = %d, itime = %d, ifuzz = %d, itimeout = %ld, timeout = %ld, next alarm = %d",
		unit->up,unit->force, unit->impulse_mode, impulse_init_time, impulse_time,
		impulse_fuzz,
		unit->impulse.expected-tstamp,unit->force_etime-atime,
		next_alarm());
	    for (c=unit->connections->next; c!=unit->connections; c=c->next) {
		if (c->timer.next == 0) c->timer.expected = tstamp;
                addr.s_addr = c->id.hdr[0].id[1] + (c->id.hdr[0].id[2]<<8)
                        + (c->id.hdr[0].id[3]<<16) + (c->id.hdr[0].id[4]<<24);
                strcpy(saddr,inet_ntoa(addr));
                addr.s_addr = c->id.hdr[0].id[5] + (c->id.hdr[0].id[6]<<8)
                        + (c->id.hdr[0].id[7]<<16) + (c->id.hdr[0].id[8]<<24);
                strcpy(daddr,inet_ntoa(addr));
                mon_syslog(LOG_DEBUG,
                        "ttl %ld, %d - %s/%d => %s/%d (tcp state ([%lx,%lx] %d,%d))",
                        c->timer.expected-tstamp,
			unit->prules[c->id.hdr[0].prule].protocol,
                        saddr, c->id.hdr[0].id[10]+(c->id.hdr[0].id[9]<<8),
                        daddr, c->id.hdr[0].id[12]+(c->id.hdr[0].id[11]<<8),
			c->tcp_state.fin_seq[0],
			c->tcp_state.fin_seq[1],
			c->tcp_state.saw_fin,
			c->tcp_state.tcp_flags);
	    }
	    return 0;
	}
	return 0;
    case IP_FW_MCONN_INIT:
	if (!req) return -1;
	{
	    FW_Connection *c;
	    for (c=unit->connections->next; c!=unit->connections; c=c->next) {
		c->bytes_total[0] += c->bytes[0];
		c->bytes_total[1] += c->bytes[1];
		c->packets[0] = c->packets[1] = c->bytes[0] = c->bytes[1] = 0;
	    }
	}
	return 0;
    case IP_FW_MCONN:
	if (!req || !monitors) return -1; /* ERRNO */
	{
	    unsigned long atime = time(0);
            unsigned long tstamp = timestamp();
	    FW_Connection *c;
#if 0
	    int i;
	    char *p;
#endif
	    char tbuf1[10], tbuf2[10], tbuf3[10];
            char buf[1024];

	    mon_cork(1);

	    sprintf(buf,"STATUS\n%d %d %d %d %d %d %s %s %s %c %c %c\n",
		unit->up, unit->force, unit->impulse_mode,
		impulse_init_time, impulse_time,
		impulse_fuzz,
		((unit->impulse.expected-tstamp > 0)
		    ? pcountdown(tbuf1, unit->impulse.expected-tstamp)
		    : pcountdown(tbuf1, 0)),
		pcountdown(tbuf2, unit->force_etime-atime),
		pcountdown(tbuf3, next_alarm()),
		(demand ? '1' : '0'),
		(blocked ? '1' : '0'),
		(forced ? '1' : '0')
	    );
	    mon_write(MONITOR_VER2|MONITOR_STATUS, buf, strlen(buf));

#if 0
	    p = buf + 7;
	    for (i=9; i > 0; i--) {
		while (*p != ' ') p++;
		*p = '\n';
	    }
	    *(p+1) = '\0';
	    mon_write(MONITOR_VER1|MONITOR_STATUS, buf, strlen(buf));
#endif

	    mon_write(MONITOR_QUEUE, "QUEUE\n", 6);
#if 1
	    mon_write(MONITOR_QUEUE2, "QUEUE\n", 6);
#endif
	    for (c=unit->connections->next; c!=unit->connections; c=c->next) {
		if (c->timer.next == 0) continue;
		strcpy(buf, c->description);
#if 0
		buf[c->desc_len] = '\n';
		buf[c->desc_len+1] = '\0';
                mon_write(MONITOR_VER1|MONITOR_QUEUE, buf, c->desc_len+1);
#endif
		c->bytes_total[0] += c->bytes[0];
		c->bytes_total[1] += c->bytes[1];
                sprintf(buf + c->desc_len,
                        "\n%8.8s %ld %ld %ld %ld %ld %ld\n",
			pcountdown(tbuf1, c->timer.expected-tstamp),
			c->packets[0], c->bytes[0], c->bytes_total[0],
			c->packets[1], c->bytes[1], c->bytes_total[1]);
		c->packets[0] = c->packets[1] = c->bytes[0] = c->bytes[1] = 0;
                mon_write(MONITOR_VER2|MONITOR_QUEUE2, buf, strlen(buf));
#if 1
		memmove(buf+52, buf+c->desc_len+1, strlen(buf+c->desc_len+1)+1);
		if (c->desc_len < 52)
			memset(buf+c->desc_len, ' ', 52 - c->desc_len);
                mon_write(MONITOR_VER2|MONITOR_QUEUE, buf, strlen(buf));
#endif
	    }
	    mon_write(MONITOR_QUEUE2, "END QUEUE\n", 10);
#if 1
	    mon_write(MONITOR_QUEUE, "END QUEUE\n", 10);
#endif
	    mon_cork(0);
	    return 0;
	}
	return 0;
    case IP_FW_PPRULE:
	if (!req) return -1; /* ERRNO */
	return 0;
    case IP_FW_PFILT:
	if (!req) return -1; /* ERRNO */
	return 0;
    /* Opening and closing firewalls is cooperative right now.
     * Also, it does nothing to change the behavior of a device
     * associated with the firewall.
     */
    case IP_FW_OPEN:
	{
	    int i;
	    for (i = 0; i < FW_NRUNIT; i++)
		if (units[i].used == 0) {
		    struct firewall_req mreq;
		    mreq.unit = i;
		    ctl_firewall(IP_FW_PFLUSH,&mreq);
		    units[i].used = 1;
		    units[i].force_etime = 0;
		    units[i].impulse_etime = 0;
		    units[i].waiting = 1;
		    return i;
		}
	    return -1;	/* ERRNO */
	}
    case IP_FW_CLOSE:
	{
	    struct firewall_req mreq;
	    if (!req) return -1; /* ERRNO */
	    mreq.unit = req->unit;
	    ctl_firewall(IP_FW_PFLUSH,&mreq);
	    unit->used = 0;
	    return 0;
	}
    case IP_FW_UP:
	unit->up = 1;
	if (ip_up)
	    run_state_script("ip-up", ip_up, 1);
	fw_force_update(unit);
	fw_impulse_update(unit,1);
	return 0;

    case IP_FW_DOWN:
	if (unit->up && ip_down)
	    run_state_script("ip-down", ip_down, 1);
	unit->up = 0;
	/* turn off the impulse generator */
	del_timer(&unit->impulse);
	unit->impulse_mode = 1;
	impulse_init_time = 0;
	return 0;
    case IP_FW_WAIT:
	return unit->waiting;
    case IP_FW_RESET_WAITING:
	unit->waiting = 1;
	return 0;
    }
    return -1; /* ERRNO */
}
